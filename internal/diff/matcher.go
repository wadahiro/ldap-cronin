package diff

import (
	"context"
	"fmt"
	"sync"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// locator finds the target entry that corresponds to one source entry.
type locator struct {
	dst    directory.Directory
	domain string
	res    identity.Resolver
	scheme identity.Scheme // the source identifier (objectGUID, entryUUID)
	prof   profile.Profile // for the DN of an entry read (plan.TargetDN)

	mu       sync.Mutex
	targetOf map[string]string // normalized source DN -> current DN on the target; only for those whose parent moved or was renamed
	found    *plan.Scope       // target DNs found by identifier or marker
	// duplicates counts searches that found more than one object.
	duplicates int
	// renamedBack maps the target DN found by GUID (normalized) to the source DN. It is used to translate references pointing at a renamed or moved object
	// back to the original DN.
	renamedBack map[string]string
}

// noteRenamed records that a target object lives at a DN different from its source DN.
func (l *locator) noteRenamed(sourceDN, targetDN string) {
	if dn.Equal(sourceDN, targetDN) {
		return
	}
	l.mu.Lock()
	l.renamedBack[dn.Normalize(targetDN)] = sourceDN
	l.mu.Unlock()
}

// translateBack translates, among the values of a target reference, the DNs of renamed or moved objects back to the source DNs.
func (l *locator) translateBack(values []string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = v
		if src, ok := l.renamedBack[dn.Normalize(dn.RefDN(v))]; ok {
			out[i] = dn.RewrapRef(v, src)
		}
	}
	return out
}

// located is the result of locate.
type located struct {
	entry   *directory.Entry
	viaGUID bool // found by identifier or marker (it was at a place other than the source DN)
	// replacedBy is the DN of a different object that sits at the source DN.
	replacedBy string
	// replacement is that different object at the DN (the one compared with the source attributes when REPLACED).
	replacement *directory.Entry
	// unmarked means the entry at the source DN carries no marker, so whether it is the cloned object cannot be told.
	unmarked bool
	// nameTaken is the DN of the entry the target answered with for the source DN, under another name it takes as the
	// same, when it is not the cloned object found elsewhere; unsure when nothing tells it is not that one renamed.
	nameTaken string
	unsure    bool
}

// locate finds the target entry that corresponds to one source entry.
// It first looks at the same DN and, with a Resolver, checks that the entry there is the cloned object. If it is a
// different object, or there is none, it looks for the cloned object elsewhere (if found, it moved).
// An entry without a marker is a different object if the cloned one is found elsewhere; otherwise it is taken at its
// DN and reported as unmarked. A create-only ancestor (ancestor) is simply taken at its DN: it may have existed on
// the target before the clone (CN=Users), so it never got a marker.
func (l *locator) locate(ctx context.Context, want directory.Entry, names []string, ancestor bool) (located, error) {
	asked := append(append([]string(nil), names...), plan.TargetDNAttrs(l.prof, want.DN)...)
	if l.res == nil {
		got, err := l.dst.Get(ctx, want.DN, asked)
		if err == nil && got != nil {
			if actual := plan.TargetDN(l.prof, want.DN, *got); !dn.Equal(actual, want.DN) {
				return located{nameTaken: actual, unsure: true}, nil
			}
		}
		return located{entry: got}, err
	}
	lookup := append(asked, l.res.Attrs()...)
	got, err := l.dst.Get(ctx, want.DN, lookup)
	if err != nil {
		return located{}, err
	}
	source, err := identity.Of(l.scheme, want)
	if err != nil {
		return located{}, fmt.Errorf("%s on the source: %w", want.DN, err)
	}
	if got != nil {
		if actual := plan.TargetDN(l.prof, want.DN, *got); !dn.Equal(actual, want.DN) {
			return l.nameTaken(ctx, source, want.DN, actual, got, lookup)
		}
	}
	if source.IsZero() {
		return located{entry: got}, nil
	}
	if got != nil {
		same, known, err := l.res.Same(source, *got)
		if err != nil {
			return located{}, err
		}
		if !known {
			if ancestor {
				return located{entry: got}, nil
			}
			// One search per unmarked entry: they are the few objects the program under test recreated or added,
			// and finding the cloned one elsewhere turns an ambiguous UNMARKED into a certain move.
			orig, err := l.find(ctx, source, want.DN, lookup)
			if err != nil {
				return located{}, err
			}
			if orig != nil {
				return located{entry: orig, viaGUID: true, replacedBy: got.DN, replacement: got}, nil
			}
			return located{entry: got, unmarked: true}, nil
		}
		if same {
			return located{entry: got}, nil
		}
		res := located{replacedBy: got.DN, replacement: got}
		orig, err := l.find(ctx, source, want.DN, lookup)
		if err != nil {
			return located{}, err
		}
		res.entry, res.viaGUID = orig, orig != nil
		return res, nil
	}
	orig, err := l.find(ctx, source, want.DN, lookup)
	if err != nil {
		return located{}, err
	}
	return located{entry: orig, viaGUID: orig != nil}, nil
}

// nameTaken says what the target answering for sourceDN with got, an entry under another name it takes as the same
// (actual), means: the cloned entry renamed to that name, the cloned one elsewhere (got being another), or neither.
func (l *locator) nameTaken(ctx context.Context, source identity.Key, sourceDN, actual string, got *directory.Entry, lookup []string) (located, error) {
	if source.IsZero() {
		return located{nameTaken: actual, unsure: true}, nil
	}
	same, known, err := l.res.Same(source, *got)
	if err != nil {
		return located{}, err
	}
	if same && known {
		got.DN = actual // a server may answer with the DN asked for (Windows)
		return located{entry: l.record(got), viaGUID: true}, nil
	}
	orig, err := l.find(ctx, source, sourceDN, lookup)
	if err != nil {
		return located{}, err
	}
	if orig != nil {
		return located{entry: orig, viaGUID: true}, nil
	}
	return located{nameTaken: actual, unsure: !known}, nil
}

// find looks for the object cloned from source somewhere other than its source DN. It first tries the expected DN:
// the same RDN under the parent's current DN when the parent moved, which explains most moves without a search.
// Otherwise it searches the whole naming context, because a move may have taken the object outside the starting
// point. The DN found is recorded.
func (l *locator) find(ctx context.Context, source identity.Key, sourceDN string, attrs []string) (*directory.Entry, error) {
	l.mu.Lock()
	parent, moved := l.targetOf[dn.Normalize(dn.Parent(sourceDN))]
	l.mu.Unlock()
	if moved {
		expected := dn.Split(sourceDN)[0] + "," + parent
		got, err := l.dst.Get(ctx, expected, attrs)
		if err != nil {
			return nil, err
		}
		if got != nil {
			same, known, err := l.res.Same(source, *got)
			if err != nil {
				return nil, err
			}
			if same && known {
				return l.record(got), nil
			}
		}
	}
	filter, ok := l.res.Filter(source)
	if !ok {
		return nil, nil
	}
	var got *directory.Entry
	hits := 0
	err := l.dst.Walk(ctx, l.domain, filter, attrs, func(e directory.Entry) error {
		if hits++; got == nil {
			c := e
			got = &c
		}
		return nil
	})
	if err != nil || got == nil {
		return nil, err
	}
	if hits > 1 {
		// A marker copied onto a new object by the program under test (or a duplicate entryUUID, which OpenLDAP
		// does not refuse). The first one wins.
		l.mu.Lock()
		l.duplicates++
		l.mu.Unlock()
	}
	return l.record(got), nil
}

func (l *locator) record(e *directory.Entry) *directory.Entry {
	l.mu.Lock()
	l.found.Add(e.DN)
	l.mu.Unlock()
	return e
}

// classify returns whether the difference between the source DN and the target DN is an RDN change (rename) or a parent change (move).
// If a parent OU moved, the expected parent is the parent's current DN on the target, and a child fully explained by
// its parent move gets false for both (so a large number of children are not reported as RENAMED).
func (l *locator) classify(sourceDN, targetDN string) (renamed, moved bool) {
	expectedParent := dn.Parent(sourceDN)
	l.mu.Lock()
	if t, ok := l.targetOf[dn.Normalize(expectedParent)]; ok {
		expectedParent = t
	}
	l.mu.Unlock()
	renamed = dn.Normalize(dn.Split(sourceDN)[0]) != dn.Normalize(dn.Split(targetDN)[0])
	moved = !dn.Equal(dn.Parent(targetDN), expectedParent)
	return renamed, moved
}

func (l *locator) noteTarget(sourceDN, targetDN string) {
	if dn.Equal(sourceDN, targetDN) {
		return
	}
	l.mu.Lock()
	l.targetOf[dn.Normalize(sourceDN)] = targetDN
	l.mu.Unlock()
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

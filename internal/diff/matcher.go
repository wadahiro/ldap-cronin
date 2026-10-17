package diff

import (
	"context"
	"fmt"
	"sync"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/plan"
)

// locator finds the target entry that corresponds to one source entry.
type locator struct {
	dst    directory.Directory
	domain string
	guids  identity.Lookup
	scheme identity.Scheme // how objects are identified across renames (objectGUID, entryUUID)

	mu       sync.Mutex
	targetOf map[string]string // normalized source DN -> current DN on the target; only for those whose parent moved or was renamed
	found    *plan.Scope       // target DNs found by GUID
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
		if src, ok := l.renamedBack[dn.Normalize(v)]; ok {
			out[i] = src
		}
	}
	return out
}

// located is the result of locate.
type located struct {
	entry   *directory.Entry
	viaGUID bool // found by GUID (it was at a place other than the source DN)
	// replacedBy is the DN of a different object that sits at the source DN.
	// It is set when the GUID in the mapping differs from the GUID of the object at that DN.
	replacedBy string
	// replacement is that different object at the DN (the one compared with the source attributes when REPLACED).
	replacement *directory.Entry
}

// locate finds the target entry that corresponds to one source entry.
// It first looks at the same DN and, if there is a mapping, checks by GUID that the entry there is the cloned object.
// If it is a different object, it looks for the original by GUID (if found, it moved elsewhere).
func (l *locator) locate(ctx context.Context, want directory.Entry, names []string) (located, error) {
	lookup := names
	if l.guids != nil {
		lookup = append(append([]string(nil), names...), l.scheme.Attr())
	}
	got, err := l.dst.Get(ctx, want.DN, lookup)
	if err != nil {
		return located{}, err
	}
	if l.guids == nil {
		return located{entry: got}, nil
	}
	source, err := identity.Of(l.scheme, want)
	if err != nil {
		return located{}, fmt.Errorf("%s on the source: %w", want.DN, err)
	}
	target, mapped := l.guids.Target(source)
	if got != nil {
		gotKey, err := identity.Of(l.scheme, *got)
		if err != nil {
			return located{}, fmt.Errorf("%s on the target: %w", got.DN, err)
		}
		if !mapped || gotKey.IsZero() || gotKey == target {
			return located{entry: got}, nil
		}
		res := located{replacedBy: got.DN, replacement: got}
		orig, err := l.findByGUID(ctx, target, names)
		if err != nil {
			return located{}, err
		}
		res.entry, res.viaGUID = orig, orig != nil
		return res, nil
	}
	if !mapped {
		return located{}, nil
	}
	orig, err := l.findByGUID(ctx, target, names)
	if err != nil {
		return located{}, err
	}
	return located{entry: orig, viaGUID: orig != nil}, nil
}

// findByGUID looks for an object by GUID across the whole target domain,
// because a move may have taken it outside the starting point. objectGUID is indexed, so this is fast. The DN found is recorded.
func (l *locator) findByGUID(ctx context.Context, target identity.Key, names []string) (*directory.Entry, error) {
	var got *directory.Entry
	err := l.dst.Walk(ctx, l.domain, l.scheme.Filter(target), names, func(e directory.Entry) error {
		if got == nil {
			c := e
			got = &c
		}
		return nil
	})
	if err != nil || got == nil {
		return nil, err
	}
	l.mu.Lock()
	l.found.Add(got.DN)
	l.mu.Unlock()
	return got, nil
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

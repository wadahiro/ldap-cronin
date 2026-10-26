// Package diff compares the clone source and the target with the same scope and attributes as clone.
// Differences are reported as soon as they are found instead of being accumulated, so memory does not grow with the
// number of entries, even when the target is empty and every entry differs. The one exception is DN reference
// attributes whose values differ: they can only be judged after every object is matched (a rename on the target
// rewrites references to it), so their values are kept until then. That grows with the number of differing
// reference values, which a verification run keeps small, not with the size of the directory.
package diff

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
	"github.com/wadahiro/ldap-cronin/internal/progress"
	"github.com/wadahiro/ldap-cronin/internal/workpool"
)

type Kind string

const (
	OnlySource Kind = "ONLY_SOURCE" // only on the source, not on the target (not cloned yet)
	OnlyTarget Kind = "ONLY_TARGET" // only on the target, not on the source
	Differ     Kind = "DIFF"        // on both sides, but attribute values differ
	// Renamed means the identifier or marker shows that the object at the source DN lives at a different DN on the
	// target. It appears when another program renamed or moved it on the target.
	Renamed Kind = "RENAMED"
	// Replaced means the source DN holds a different object from the one that was cloned (its identifier or
	// marker names another object), and the original object exists nowhere. It appears when the object was deleted
	// and recreated at the same DN with the identifier of another, or a copied marker.
	Replaced Kind = "REPLACED"
	// Unmarked means the entry at the source DN carries no marker. It may have been deleted and recreated, had its
	// marker removed, or been added to the source after the clone; a marker cannot tell these apart. Its attributes
	// are still compared.
	Unmarked Kind = "UNMARKED"
	// NameTaken means the target answers for the source DN with another entry, whose name it takes as the same
	// (Windows ignores width and kana type, Samba collapses spaces): clone did not add the source entry, as writing
	// it would have overwritten that one. Unsure is set when no marker or identifier tells it is not this entry
	// renamed.
	NameTaken Kind = "NAME_TAKEN"
	// NotWritable means the target refuses the source entry (on Windows the leftover of a name conflict, whose RDN
	// holds a line feed, and an RDN or a sAMAccountName longer than it takes), so clone did not add it; Why says so.
	NotWritable Kind = "NOT_WRITABLE"
)

type Difference struct {
	Kind   Kind
	DN     string
	Attr   string
	Source []string
	Target []string
	// For multi-valued attributes, which side alone holds each value (listing all values would make member and the like unreadable).
	OnlySource []string
	OnlyTarget []string
	Multi      bool
	// CaseOnly means the difference is only in letter case. For a single value, the two values are equal ignoring case;
	// for multi-valued attributes, every differing value has a counterpart on the other side that differs only in case. It still counts as a difference.
	CaseOnly bool
	// For multi-valued attributes, whether each OnlySource / OnlyTarget value has a counterpart on the other side that differs only in case.
	SourceCasePair []bool
	TargetCasePair []bool

	// For Renamed, the current DN on the target and whether it is a rename (RDN change) or a move (parent change);
	// for NameTaken, the target's entry that holds the name, and Unsure.
	TargetDN   string
	RDNRenamed bool
	Moved      bool
	Unsure     bool
	// For NotWritable, why the target refuses it.
	Why string
}

// Summary is the compared scope and the number of differences.
type Summary struct {
	Compared    map[string]int // number of objects compared per kind
	Differences map[Kind]int
	CaseOnly    int // number of DIFF entries that differ only in case

	// Matching says how renames and moves were detected (the Resolver's Describe); empty when they were not.
	Matching   string
	Implied    int // number not reported as RENAMED because a parent OU move or rename explains them
	Duplicates int // number of objects found more than once by identifier or marker (the first was used)
	// NotCompared counts, per reference attribute, the source values clone cannot write (they name an entry the
	// target lacks, on a server that needs it), so diff does not compare them.
	NotCompared map[string]int
	// NotComparedWhy is NotCompared per "attribute: why" (plan.Classifier.Why), for the text summary.
	NotComparedWhy map[string]int
	// Withheld counts, per attribute, the source values clone does not write because the target holds each once and a
	// replication-conflict leftover shares it (plan.Withheld), so diff does not compare them; WithheldWhy says why.
	Withheld    map[string]int
	WithheldWhy string
	// ACEsNotCompared counts, per why (plan.WhyNoSourcePrincipal ...), the source's ACEs clone leaves out because
	// the target has no principal for their trustee (ACLTranslated, plan.Job.SDValues).
	ACEsNotCompared map[string]int
	// Referenced is the number of entries outside the scope compared because a reference names them.
	Referenced int
	// Holders is the number of groups outside the scope whose values naming entries of it were compared
	// (plan.Holder); Unheld counts those clone leaves as they are, per why.
	Holders int
	Unheld  map[string]int
	// NotCloned counts the entries under base_dn of no enabled kind, per structural object class: clone does not
	// copy them, so diff does not compare them either (plan.Unselected).
	NotCloned map[string]int
	// Placeholders counts the placeholders clone created under base_dn (plan.Placeholder), which are not
	// ONLY_TARGET: the source did not return what they stand for.
	Placeholders int
}

// Options are the run-time settings of a comparison.
type Options struct {
	Workers int
	// Resolver finds the target object of a source object by identifier or marker, so renames and moves made on
	// the target are reported as RENAMED. nil: off.
	Resolver identity.Resolver
	// Progress, when set, is told the phases and how far each is (nil: nothing is shown).
	Progress *progress.Bar
}

// Run reports each difference to emit one at a time. emit is not called from multiple goroutines.
// Masked attributes are not compared, since their values are expected to differ.
// DN reference attributes are compared in full, except for the source values clone cannot write (see Summary.NotCompared).
//
// With a Lookup, objects whose source DN is missing on the target are looked up by identifier, and reported as
// RENAMED if found at a different DN. This verifies changes made by another program that renamed or moved objects on the target.
func Run(ctx context.Context, src, dst directory.Directory, job plan.Job, o Options, emit func(Difference)) (Summary, error) {
	r := &runner{job: job, emit: emit, outside: map[string]string{}, sum: Summary{Compared: map[string]int{}, Differences: map[Kind]int{}, NotCompared: map[string]int{}, NotComparedWhy: map[string]int{}, Unheld: map[string]int{}, ACEsNotCompared: map[string]int{}},
		primaryOutside: map[string]string{}, held: map[string]bool{}}
	if o.Resolver != nil {
		r.sum.Matching = o.Resolver.Describe()
	}
	bar := o.Progress
	bar.Phase("reading the source", -1)
	read := plan.Read{Identity: o.Resolver != nil}
	if pg := job.Profile.PrimaryGroup; pg != nil {
		read.Extra = []string{pg.Attr()}
	}
	if job.ACL != plan.ACLNone {
		read.Extra = append(read.Extra, sdAttr)
	}
	p, err := plan.Build(ctx, src, job, read)
	if err != nil {
		return r.sum, err
	}
	r.p, r.ctx = p, ctx
	r.sdOn = job.Translated()
	// The values clone withholds are not compared; a clash stops clone, not diff.
	if r.withheld, _, err = p.Withholding(ctx, dst); err != nil {
		return r.sum, err
	}
	if job.ACL == plan.ACLTranslated || len(r.sdOn) > 0 {
		if r.principals, err = p.Principals(ctx, dst); err != nil {
			return r.sum, err
		}
	}
	if err := r.readGroups(ctx, dst); err != nil {
		return r.sum, err
	}
	bar.Stats(func() string {
		r.mu.Lock()
		defer r.mu.Unlock()
		compared, differences := 0, 0
		for _, n := range r.sum.Compared {
			compared += n
		}
		for _, n := range r.sum.Differences {
			differences += n
		}
		return fmt.Sprintf("compared %d · differences %d", compared, differences)
	})
	bar.Phases(len(p.Leaves()) + 2) // the parents, each leaf kind, the references and the target
	bar.Phase("OUs and parents", len(p.Containers))
	r.loc = &locator{scheme: job.Profile.Identity, prof: job.Profile, dst: dst, domain: p.Root, res: o.Resolver,
		targetOf: map[string]string{}, found: plan.NewScope(), renamedBack: map[string]string{}}
	// Containers and parent leaves go shallowest first: to know the expected parent DN of a child, where its parent
	// lives on the target (whether it moved) must already be known.
	if err := p.EachLevel(ctx, o.Workers, func(ctx context.Context, n plan.Node) error {
		defer bar.Add(1)
		names := []string{"objectClass"}
		switch {
		case n.Outside:
			names = r.withPrimary(n.Kind, r.withoutRefs(n.Kind.Attrs))
			r.referenced()
		case n.Kind != nil:
			names = r.withPrimary(n.Kind, n.Kind.Attrs)
			r.compared(n.Kind.Name)
			r.noteOutside(n.Entry, names)
		}
		return r.check(ctx, n.Entry, names, n.Kind, true)
	}); err != nil {
		return r.sum, err
	}
	for _, k := range p.Leaves() {
		bar.Phase(k.Name, p.LeafCount(k))
		if err := p.EachLeafOf(ctx, o.Workers, k, func(ctx context.Context, k *plan.Kind, want directory.Entry) error {
			defer bar.Add(1)
			r.compared(k.Name)
			r.noteOutside(want, k.Attrs)
			return r.check(ctx, want, r.withPrimary(k, k.Attrs), k, false)
		}); err != nil {
			return r.sum, err
		}
	}
	bar.Phase("references, and what only the target has", -1)
	if r.sum.NotCloned, err = p.Unselected(ctx); err != nil {
		return r.sum, err
	}
	refs := p.Classifier(dst)
	// Referenced objects first: a rename of one on the target must be known before the references are compared.
	if err := r.checkReferenced(ctx, refs, o.Workers); err != nil {
		return r.sum, err
	}
	if err := r.resolveRefs(ctx, refs); err != nil {
		return r.sum, err
	}
	if err := r.checkHolders(ctx, dst, o.Workers); err != nil {
		return r.sum, err
	}
	if err := r.checkPrimaryGroups(ctx, o.Workers); err != nil {
		return r.sum, err
	}
	if r.aclErr != nil {
		return r.sum, r.aclErr
	}
	r.sum.Duplicates = r.loc.duplicates

	for _, k := range job.Kinds {
		err := plan.WalkBases(ctx, dst, job.BaseDNs, k.Filter, []string{"description"}, func(e directory.Entry) error {
			// Entries matched by identifier are RENAMED (or already explained by a parent move), so they are not target-only.
			if !p.Scope.Has(e.DN) && !r.loc.found.Has(e.DN) {
				if plan.IsPlaceholder(e) { // where a reference names an entry the source did not return
					r.mu.Lock()
					r.sum.Placeholders++
					r.mu.Unlock()
					return nil
				}
				r.report(Difference{Kind: OnlyTarget, DN: e.DN})
			}
			return nil
		})
		if err != nil {
			return r.sum, fmt.Errorf("scan target %s: %w", k.Name, err)
		}
	}
	return r.sum, nil
}

// runner is the state of one comparison. Workers share it, so everything that changes is behind a mutex.
type runner struct {
	job plan.Job
	// dstGroups maps the RID of each target group to its DN, for the primary groups (readGroups).
	dstGroups map[string]string
	ctx       context.Context // the run's, for the source's groups read on the first primary group that needs them
	// primaryOutside are the primary groups outside the scope met while comparing (normalized DN -> DN), and held
	// the holders checkHolders compared as groups; primaryErr the first error reading the source's groups.
	primaryMu      sync.Mutex
	primaryOutside map[string]string
	held           map[string]bool
	primaryErr     error
	// principals gives the source's SIDs the target's (ACLTranslated, sdOn); aclErr is the first error doing it
	// (aclFailed). sdOn are the values naming principals compared translated (plan.Job.Translated).
	principals *plan.Principals
	sdOn       map[string]string
	withheld   *plan.Withheld // the source's values clone does not write (plan.Withholding)
	aclErr     error
	p          *plan.Plan
	loc        *locator
	emit       func(Difference)

	mu  sync.Mutex // guards sum and serializes emit
	sum Summary

	pendMu  sync.Mutex
	pending []pendingRef      // reference attributes judged after every object is matched
	outside map[string]string // normalized DN -> DN of every reference value outside the scope (guarded by pendMu)
}

// noteOutside records the reference values of want that name entries outside the scope: those of a kind are
// referenced objects, which clone creates and diff compares (checkReferenced).
func (r *runner) noteOutside(want directory.Entry, names []string) {
	r.pendMu.Lock()
	defer r.pendMu.Unlock()
	for _, n := range names {
		if !r.p.IsRef(n) {
			continue
		}
		for _, v := range want.Values(n) {
			if d := dn.RefDN(v); !r.p.Scope.Has(d) {
				r.outside[dn.Normalize(d)] = d
			}
		}
	}
}

// checkReferenced compares the referenced objects (plan.RefReferenced) as their kind, without their own references,
// which clone does not apply either.
func (r *runner) checkReferenced(ctx context.Context, refs *plan.Classifier, workers int) error {
	values := make([]string, 0, len(r.outside))
	for _, v := range r.outside {
		values = append(values, v)
	}
	sort.Strings(values)
	return workpool.Each(ctx, workers, values, func(ctx context.Context, v string) error {
		k, err := refs.Referenced(ctx, v)
		if err != nil || k == nil {
			return err
		}
		e, err := r.p.ReadReferenced(ctx, v, k)
		if err != nil || e == nil {
			return err
		}
		r.referenced()
		return r.check(ctx, *e, r.withPrimary(k, r.withoutRefs(k.Attrs)), k, false)
	})
}

// withoutRefs returns names without the DN reference attributes.
func (r *runner) withoutRefs(names []string) []string {
	var out []string
	for _, n := range names {
		if !r.p.IsRef(n) {
			out = append(out, n)
		}
	}
	return out
}

func (r *runner) referenced() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sum.Referenced++
}

func (r *runner) report(d Difference) {
	if d.Kind == Differ && profile.Set(r.job.Profile.CopiedSecrets)[strings.ToLower(d.Attr)] {
		d = fingerprinted(d)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sum.Differences[d.Kind]++
	if d.Kind == Differ && d.CaseOnly {
		r.sum.CaseOnly++
	}
	r.emit(d)
}

func (r *runner) compared(kind string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sum.Compared[kind]++
}

func (r *runner) implied() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sum.Implied++
}

// check matches one source entry against the target and reports the differences.
// An entry without a kind (a create-only ancestor) is checked only for existence, rename and move.
// structural entries also record where they live on the target, for the expected parent of their children.
func (r *runner) check(ctx context.Context, want directory.Entry, names []string, kind *plan.Kind, structural bool) error {
	if why := r.withheld.RefusedEntryWhy(want); why != "" {
		r.report(Difference{Kind: NotWritable, DN: want.DN, Why: why})
		return nil
	}
	want = r.withoutRefused(want)
	if kind != nil {
		var stripped []string
		if want, stripped = r.withheld.Strip(want); len(stripped) > 0 {
			r.mu.Lock()
			if r.sum.Withheld == nil {
				r.sum.Withheld, r.sum.WithheldWhy = map[string]int{}, r.withheld.Why
			}
			for _, n := range stripped {
				r.sum.Withheld[n]++
			}
			r.mu.Unlock()
		}
	}
	res, err := r.loc.locate(ctx, want, names, kind == nil)
	if err != nil {
		return err
	}
	if res.nameTaken != "" {
		r.report(Difference{Kind: NameTaken, DN: want.DN, TargetDN: res.nameTaken, Unsure: res.unsure})
		return nil
	}
	if res.unmarked {
		r.report(Difference{Kind: Unmarked, DN: want.DN})
	}
	if res.replacedBy != "" {
		if res.entry == nil { // the original object is gone and a different object sits at the same DN
			r.report(Difference{Kind: Replaced, DN: want.DN})
			// Even for a different object we want to know how it differs from the source values, so compare the attributes.
			if kind != nil {
				r.compareEntry(kind.Name, want, *res.replacement, names, "")
			}
			return nil
		}
		// The original object moved elsewhere and a different object was created at the original DN. The latter is not on the source.
		r.report(Difference{Kind: OnlyTarget, DN: res.replacedBy})
	}
	got, viaGUID := res.entry, res.viaGUID
	if got == nil {
		r.report(Difference{Kind: OnlySource, DN: want.DN})
		return nil
	}
	shown := want
	skip := "" // attribute not compared because a rename explains it (the RDN attribute)
	if viaGUID {
		r.loc.noteRenamed(want.DN, got.DN)
		renamed, moved := r.loc.classify(want.DN, got.DN)
		if renamed {
			// Changing the RDN makes the server change cn (ou for an OU) as well. It is a result of the rename, so it is not reported as a separate difference.
			// If the target value disagrees with the new RDN, however, that is a real difference and is reported.
			if typ, val, ok := dn.FirstRDN(got.DN); ok && strings.EqualFold(first(got.Values(typ)), val) {
				skip = typ
			}
		}
		if renamed || moved {
			r.report(Difference{Kind: Renamed, DN: want.DN, TargetDN: got.DN, RDNRenamed: renamed, Moved: moved})
		} else {
			r.implied()
		}
		shown.DN = got.DN // attribute differences are shown at the current location on the target
	}
	if structural {
		r.loc.noteTarget(want.DN, got.DN)
	}
	if kind != nil {
		r.compareEntry(kind.Name, shown, *got, names, skip)
	}
	return nil
}

// fingerprinted is d with each value of a credential replaced by a fingerprint: enough to see that it changed and
// which value went where, never the value. Every output (the text, JSON lines) goes through report, so none prints it.
func fingerprinted(d Difference) Difference {
	hide := func(values []string) []string {
		if values == nil {
			return nil
		}
		out := make([]string, len(values))
		for i, v := range values {
			sum := sha256.Sum256([]byte(v))
			out[i] = fmt.Sprintf("(credential, sha256 %x)", sum[:6])
		}
		return out
	}
	d.Source, d.Target, d.OnlySource, d.OnlyTarget = hide(d.Source), hide(d.Target), hide(d.OnlySource), hide(d.OnlyTarget)
	d.CaseOnly, d.SourceCasePair, d.TargetCasePair = false, nil, nil // case markers would point into the value
	return d
}

// withoutRefused is want without the reference values naming entries the target refuses (clone does not add them,
// nor write those values), counted as not compared.
func (r *runner) withoutRefused(want directory.Entry) directory.Entry {
	if !r.withheld.Refuses() {
		return want
	}
	var out *directory.Entry
	for n, vs := range want.Attrs {
		if !r.p.IsRef(n) {
			continue
		}
		var keep []string
		for _, v := range vs {
			why := r.withheld.RefusedWhy(dn.RefDN(v))
			if why == "" {
				keep = append(keep, v)
				continue
			}
			r.mu.Lock()
			r.sum.NotCompared[n]++
			r.sum.NotComparedWhy[n+": names an entry not added: "+why]++
			r.mu.Unlock()
		}
		if len(keep) == len(vs) {
			continue
		}
		if out == nil {
			c := directory.Entry{DN: want.DN, Attrs: make(map[string][]string, len(want.Attrs))}
			for k, v := range want.Attrs {
				c.Attrs[k] = v
			}
			out = &c
		}
		if len(keep) == 0 {
			delete(out.Attrs, n)
		} else {
			out.Attrs[n] = keep
		}
	}
	if out == nil {
		return want
	}
	return *out
}

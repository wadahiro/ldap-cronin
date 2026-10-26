package diff

import (
	"context"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/compare"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/plan"
)

// compareEntry reports the attribute differences of one matched entry of kind. Masked attributes (on every entry,
// or on the kind's) are not compared, since their values are expected to differ, nor is skip (an RDN attribute that
// a rename explains).
func (r *runner) compareEntry(kind string, want, got directory.Entry, names []string, skip string) {
	want, got = r.primaryDNs(want, got)
	// Only where the SD is compared (not a holder's): the ACEs left out would be counted for nothing otherwise.
	for _, n := range names {
		switch {
		case strings.EqualFold(n, sdAttr):
			want, got = r.aclTexts(want, got)
		case r.sdOn[strings.ToLower(n)] != "":
			want, got = r.descriptorTexts(want, got, n, true)
		}
	}
	plain, refs := r.p.Changes(want, got, names, func(name string) bool {
		return r.job.Masker.MaskedIn(kind, name) || (skip != "" && strings.EqualFold(name, skip))
	})
	for _, c := range plain {
		r.report(makeDifference(want.DN, c.Name, c.Want, c.Got, r.p.Normalizer(c.Name), false))
	}
	if len(refs) == 0 {
		return
	}
	// The server rewrites a reference pointing at an object renamed on the target to the new DN.
	// Which objects were renamed is unknown until everything has been matched,
	// so only the values that differ as they are get set aside, and are translated and compared later (resolveRefs).
	r.pendMu.Lock()
	defer r.pendMu.Unlock()
	for _, c := range refs {
		r.pending = append(r.pending, pendingRef{dn: want.DN, name: c.Name,
			want: append([]string(nil), c.Want...), got: append([]string(nil), c.Got...)})
	}
}

// makeDifference turns one attribute difference into its display form.
func makeDifference(dn, name string, w, g []string, n compare.Normalizer, isRef bool) Difference {
	d := Difference{Kind: Differ, DN: dn, Attr: name, Source: w, Target: g}
	if len(w) > 1 || len(g) > 1 {
		d.Multi = true
		d.OnlySource, d.OnlyTarget = compare.SetDiff(n, w, g)
		d.Source, d.Target = nil, nil // do not keep or print all values
		if !isRef {                   // DN reference attributes are already normalized as DNs, so case-only differences cannot occur
			d.SourceCasePair, d.TargetCasePair, d.CaseOnly = casePairs(d.OnlySource, d.OnlyTarget)
		}
	} else if len(w) == 1 && len(g) == 1 && strings.EqualFold(w[0], g[0]) {
		d.CaseOnly = true
	}
	return d
}

// pendingRef is a DN reference attribute whose comparison was deferred.
type pendingRef struct {
	dn, name  string
	want, got []string
}

// resolveRefs compares the deferred DN reference attributes. Among the target values, the new DNs of renamed or
// moved objects are translated back to the original (source) DNs. Every value is compared except the source's
// values clone cannot write (plan.RefUnreproducible), which are counted instead: a member removed or added on the
// target shows, whatever it names.
func (r *runner) resolveRefs(ctx context.Context, refs *plan.Classifier) error {
	for _, pr := range r.pending {
		var w []string
		for _, v := range pr.want {
			class, err := refs.Class(ctx, v)
			if err != nil {
				return err
			}
			if class.Reproducible() {
				w = append(w, v)
				continue
			}
			why, err := refs.Why(ctx, v)
			if err != nil {
				return err
			}
			r.mu.Lock()
			r.sum.NotCompared[pr.name]++
			r.sum.NotComparedWhy[pr.name+": "+why]++
			r.mu.Unlock()
		}
		g := r.loc.translateBack(pr.got)
		if r.p.Equal(pr.name, w, g) {
			continue
		}
		r.report(makeDifference(pr.dn, pr.name, w, g, r.p.Normalizer(pr.name), true))
	}
	return nil
}

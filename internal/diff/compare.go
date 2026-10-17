package diff

import (
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/compare"
	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// compareEntry reports the attribute differences of one matched entry. Masked attributes are not compared, since
// their values are expected to differ, nor is skip (an RDN attribute that a rename explains).
func (r *runner) compareEntry(want, got directory.Entry, names []string, skip string) {
	plain, refs := r.p.Changes(want, got, names, func(name string) bool {
		return r.job.Masker.Masked(name) || (skip != "" && strings.EqualFold(name, skip))
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

// resolveRefs compares the deferred DN reference attributes. Among the target values, the new DNs of renamed or moved objects
// are translated back to the original (source) DNs, then filtered by the plan scope and compared.
func (r *runner) resolveRefs() {
	for _, pr := range r.pending {
		w, g := r.p.InScope(pr.want), r.p.InScope(r.loc.translateBack(pr.got))
		if r.p.Equal(pr.name, w, g) {
			continue
		}
		r.report(makeDifference(pr.dn, pr.name, w, g, r.p.Normalizer(pr.name), true))
	}
}

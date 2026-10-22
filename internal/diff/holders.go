package diff

import (
	"context"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/workpool"
)

// checkHolders compares the groups outside the scope that hold entries of it (plan.Holder), as clone gives them
// those entries: a group clone created is compared as its kind, without its own references (unless a reference
// named it, which compared it already); on every one, the values of its forward links that name entries of the
// scope, on the target after translating the renamed ones back. The rest of their values are not clone's.
func (r *runner) checkHolders(ctx context.Context, dst directory.Directory, workers int) error {
	hs, err := r.p.Holders(ctx)
	if err != nil || len(hs) == 0 {
		return err
	}
	return workpool.Each(ctx, workers, hs, func(ctx context.Context, h plan.Holder) error {
		if h.Why != "" {
			r.unheld(h.Why)
			return nil
		}
		cur, err := dst.Get(ctx, h.DN, append([]string{"objectClass"}, h.Attrs...))
		if err != nil {
			return err
		}
		switch {
		case cur == nil && h.Builtin:
			r.unheld("is a built-in group the target lacks")
			return nil
		case cur == nil && h.Existing:
			r.unheld("is a group outside the scope the target lacks ([scope] outside_groups = \"existing\")")
			return nil
		case !h.Builtin && !h.Existing && !r.namedOutside(h.DN):
			r.primaryMu.Lock()
			r.held[dn.Normalize(h.DN)] = true
			r.primaryMu.Unlock()
			e, err := r.p.ReadReferenced(ctx, h.DN, h.Kind)
			if err != nil || e == nil {
				return err
			}
			r.referenced()
			if err := r.check(ctx, *e, r.withoutRefs(h.Kind.Attrs), h.Kind, false); err != nil {
				return err
			}
		}
		r.mu.Lock()
		r.sum.Holders++
		r.mu.Unlock()
		if cur == nil {
			return nil // reported as ONLY_SOURCE by check
		}
		for _, name := range h.Attrs {
			want, err := r.p.HolderValues(ctx, h, name)
			if err != nil {
				return err
			}
			got := r.p.InScope(r.loc.translateBack(cur.Values(name)))
			if !r.p.Equal(name, want, got) {
				r.report(makeDifference(h.DN, name, want, got, r.p.Normalizer(name), true))
			}
		}
		return nil
	})
}

// namedOutside reports whether a reference of the scope named the entry, so checkReferenced compared it.
func (r *runner) namedOutside(entryDN string) bool {
	r.pendMu.Lock()
	defer r.pendMu.Unlock()
	_, ok := r.outside[dn.Normalize(entryDN)]
	return ok
}

func (r *runner) unheld(why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sum.Unheld[why]++
}

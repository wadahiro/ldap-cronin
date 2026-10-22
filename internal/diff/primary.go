package diff

import (
	"context"
	"sort"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/workpool"
)

// readGroups reads the target's groups by RID, for the primary groups (profile.PrimaryGrouper), once before the
// comparison. The source's are read only for a primary group that is not a built-in one (plan.PrimaryGroupDN).
func (r *runner) readGroups(ctx context.Context, dst directory.Directory) error {
	pg := r.job.Profile.PrimaryGroup
	if pg == nil {
		return nil
	}
	r.ctx = ctx
	var err error
	r.dstGroups, err = pg.Groups(ctx, dst, r.p.Root)
	return err
}

// withPrimary adds the primary group attribute to names for an account kind, so it is read on both sides and
// compared as the group it names.
func (r *runner) withPrimary(k *plan.Kind, names []string) []string {
	pg := r.job.Profile.PrimaryGroup
	if pg == nil || k == nil || !k.Account {
		return names
	}
	return append(append([]string(nil), names...), pg.Attr())
}

// primaryDNs replaces the RID of the primary group on each side with the DN of the group it names there: a group
// created over LDAP has the target's own RID, and the source's DN.
func (r *runner) primaryDNs(want, got directory.Entry) (directory.Entry, directory.Entry) {
	pg := r.job.Profile.PrimaryGroup
	if pg == nil {
		return want, got
	}
	translate := func(e directory.Entry, lookup func(string) string) directory.Entry {
		values := e.Values(pg.Attr())
		if len(values) == 0 {
			return e
		}
		rid := strings.TrimSpace(values[0])
		d := lookup(rid)
		if d == "" {
			d = "RID " + rid + " (no group of the domain)"
		}
		out := directory.Entry{DN: e.DN, Attrs: make(map[string][]string, len(e.Attrs))}
		for n, vs := range e.Attrs {
			if strings.EqualFold(n, pg.Attr()) {
				vs = []string{d}
			}
			out.Attrs[n] = vs
		}
		return out
	}
	want = translate(want, func(rid string) string {
		if pg.WellKnown(rid) {
			return r.dstGroups[rid] // the same group in every domain, which a dump need not carry
		}
		d, err := r.p.PrimaryGroupDN(r.ctx, rid)
		r.primaryMu.Lock()
		defer r.primaryMu.Unlock()
		if err != nil && r.primaryErr == nil {
			r.primaryErr = err
		}
		if d != "" && !r.p.Scope.Has(d) {
			r.primaryOutside[dn.Normalize(d)] = d // compared as a group outside the scope (checkPrimaryGroups)
		}
		return d
	})
	got = translate(got, func(rid string) string { return r.dstGroups[rid] })
	return want, got
}

// checkPrimaryGroups compares the primary groups outside the scope clone created (a user's group of another OU that
// no reference names and no memberOf lists), as their kind, without their own references; a built-in one is the
// target's own.
func (r *runner) checkPrimaryGroups(ctx context.Context, workers int) error {
	r.primaryMu.Lock()
	err := r.primaryErr
	var groups []string
	for key, d := range r.primaryOutside {
		if !r.namedOutside(d) && !r.held[key] {
			groups = append(groups, d)
		}
	}
	r.primaryMu.Unlock()
	if err != nil {
		return err
	}
	sort.Strings(groups)
	return workpool.Each(ctx, workers, groups, func(ctx context.Context, d string) error {
		h, err := r.p.Holder(ctx, d)
		if err != nil || h.Why != "" || h.Builtin || h.Existing {
			return err
		}
		e, err := r.p.ReadReferenced(ctx, d, h.Kind)
		if err != nil || e == nil {
			return err
		}
		r.referenced()
		return r.check(ctx, *e, r.withoutRefs(h.Kind.Attrs), h.Kind, false)
	})
}

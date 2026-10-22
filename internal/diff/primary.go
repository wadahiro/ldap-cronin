package diff

import (
	"context"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/plan"
)

// readGroups reads the groups of both sides by RID, for the primary groups (profile.PrimaryGrouper): once, before
// the comparison.
func (r *runner) readGroups(ctx context.Context, dst directory.Directory) error {
	pg := r.job.Profile.PrimaryGroup
	if pg == nil {
		return nil
	}
	if _, err := r.p.PrimaryGroupDN(ctx, ""); err != nil {
		return err
	}
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
		d, _ := r.p.PrimaryGroupDN(context.Background(), rid) // read by readGroups already
		return d
	})
	got = translate(got, func(rid string) string { return r.dstGroups[rid] })
	return want, got
}

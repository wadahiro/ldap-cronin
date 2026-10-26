package clone

import (
	"context"
	"fmt"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/workpool"
)

// sdValue is a source value naming principals by SID (plan.Job.SDValues), to write with the target's.
type sdValue struct{ dn, attr, raw string }

// withSDValues notes the values of e that writeSDValues writes; upsert left them out (desired).
func (r *runner) withSDValues(e directory.Entry) {
	if len(r.sdOn) == 0 {
		return
	}
	for n, v := range e.Attrs {
		if name := r.sdOn[strings.ToLower(n)]; name != "" && len(v) > 0 {
			r.mu.Lock()
			r.sdValues = append(r.sdValues, sdValue{dn: e.DN, attr: name, raw: v[0]})
			r.mu.Unlock()
		}
	}
}

// writeSDValues writes each value naming principals with each SID the target's (plan.Principals), as descriptors
// does an ACL, and after every object exists for the same reason: the principal a delegation names may be one clone
// creates late (a group outside the scope). An ACE whose trustee has no principal on the target is left out, with a
// warning per trustee: it would let nobody act as the account. Written with the entry instead, the value would name
// the source's SIDs, nobody on a target of its own domain SID.
func (r *runner) writeSDValues(ctx context.Context, p *plan.Plan) error {
	if len(r.sdValues) == 0 {
		return nil
	}
	d := r.prof.Descriptors
	t, err := r.principalsFor(ctx, p)
	if err != nil {
		return err
	}
	if r.opt.DryRun {
		r.logf("# the values naming principals below name the source's SIDs: a dry-run cannot read the target's\n")
	}
	r.opt.Progress.Phase("values naming principals", len(r.sdValues))
	return workpool.Each(ctx, r.opt.Workers, r.sdValues, func(ctx context.Context, v sdValue) error {
		defer r.opt.Progress.Add(1)
		cur := ""
		if e, err := r.dst.Get(ctx, v.dn, []string{v.attr}); err != nil {
			return err
		} else if e != nil {
			cur = first(e.Values(v.attr))
		}
		reasons := map[string]string{}
		out, dropped, err := d.Rewrite(v.raw, cur, func(sid string) (string, error) {
			to, why, err := t.Target(ctx, sid)
			reasons[sid] = why
			return to, err
		})
		if err != nil {
			return fmt.Errorf("%s: the source's %s: %w", v.dn, v.attr, err)
		}
		for _, sid := range dropped {
			r.leftOutACE(v.dn, v.attr, sid, reasons[sid])
		}
		if cur != "" && sameParts(d.Parts, out, cur) {
			return nil
		}
		if err := r.dst.Replace(ctx, v.dn, map[string][]string{v.attr: {out}}); err != nil {
			return fmt.Errorf("%s: the source's %s: %w", v.dn, v.attr, err)
		}
		r.count(func(rep *Report) { rep.SDValues[v.attr]++ })
		r.logf("update %s (%s)\n", v.dn, v.attr)
		return nil
	})
}

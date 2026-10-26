package clone

import (
	"context"
	"fmt"

	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/workpool"
)

// withACL notes an object clone wrote as one to give the source's ACL. A create-only ancestor (CN=Users, the
// containers above base_dn) is not one: it is the target's own, and on a domain of one's own its ACL is not clone's
// to change.
func (r *runner) withACL(dn string) {
	if !r.aclOn {
		return
	}
	r.mu.Lock()
	r.acls = append(r.acls, dn)
	r.mu.Unlock()
}

// descriptors gives each object clone wrote the source's owner, group and explicit ACEs, each SID the target's
// (plan.Principals): the target computes the inherited ACEs from the object's parents. An ACE whose trustee has no
// principal on the target is left out, with a warning per trustee; it would grant or deny nobody there anyway.
func (r *runner) descriptors(ctx context.Context, p *plan.Plan) error {
	if !r.aclOn || len(r.acls) == 0 {
		return nil
	}
	d := r.prof.Descriptors
	t, err := r.principalsFor(ctx, p)
	if err != nil {
		return err
	}
	if r.opt.DryRun {
		r.logf("# the ACLs below name the source's SIDs: a dry-run cannot read the target's\n")
	}
	r.opt.Progress.Phase("ACLs", len(r.acls))
	none := 0
	err = workpool.Each(ctx, r.opt.Workers, r.acls, func(ctx context.Context, dn string) error {
		defer r.opt.Progress.Add(1)
		raw, err := t.Descriptor(ctx, dn)
		if err != nil {
			return err
		}
		if raw == "" {
			r.mu.Lock()
			none++
			r.mu.Unlock()
			return nil
		}
		cur := ""
		if e, err := r.dst.Get(ctx, dn, []string{d.Attr()}); err != nil {
			return err
		} else if e != nil {
			cur = first(e.Values(d.Attr()))
		}
		reasons := map[string]string{}
		out, dropped, err := d.Rewrite(raw, cur, func(sid string) (string, error) {
			to, why, err := t.Target(ctx, sid)
			reasons[sid] = why
			return to, err
		})
		if err != nil {
			return fmt.Errorf("%s: the source's %s: %w", dn, d.Attr(), err)
		}
		for _, sid := range dropped {
			r.leftOutACE(dn, d.Attr(), sid, reasons[sid])
		}
		if cur != "" && sameParts(d.Parts, out, cur) {
			return nil
		}
		if err := r.dst.Replace(ctx, dn, map[string][]string{d.Attr(): {out}}); err != nil {
			return fmt.Errorf("%s: the source's %s: %w", dn, d.Attr(), err)
		}
		r.count(func(rep *Report) { rep.ACLs++ })
		r.logf("update %s (%s)\n", dn, d.Attr())
		return nil
	})
	if err != nil {
		return err
	}
	if none == len(r.acls) {
		r.warn("the source gave no %s (a dump taken without them, or an account that may not read them): the objects keep the target's ACLs", d.Attr())
	}
	return nil
}

// principalsFor is the one plan.Principals of the run, which the ACLs and the values naming principals share (and
// its cache).
func (r *runner) principalsFor(ctx context.Context, p *plan.Plan) (*plan.Principals, error) {
	if r.principals != nil {
		return r.principals, nil
	}
	var dst = r.dst
	if r.opt.DryRun {
		dst = nil // its target holds no SIDs: the LDIF carries the source's
	}
	t, err := p.Principals(ctx, dst)
	r.principals = t
	return t, err
}

// leftOutACE counts an ACE left out of attr of dn, and warns once per trustee.
func (r *runner) leftOutACE(dn, attr, sid, why string) {
	if why == "" {
		why = plan.WhyNoTargetPrincipal
	}
	r.mu.Lock()
	r.report.ACEsLeftOut[why]++
	first := !r.leftOut[sid]
	if first && len(r.leftOut) < maxWarnings {
		r.leftOut[sid] = true
	}
	r.mu.Unlock()
	if first {
		r.warn("leave the ACEs naming %s out (first of %s on %s): it %s", sid, attr, dn, why)
	}
}

// sameParts reports whether two descriptors give the same owner, group, protected flag and explicit ACEs, in any
// order: the server may order the ACEs its own way.
func sameParts(parts func(string) ([]string, error), a, b string) bool {
	pa, err := parts(a)
	if err != nil {
		return false
	}
	pb, err := parts(b)
	if err != nil || len(pa) != len(pb) {
		return false
	}
	count := map[string]int{}
	for _, v := range pa {
		count[v]++
	}
	for _, v := range pb {
		if count[v]--; count[v] < 0 {
			return false
		}
	}
	return true
}

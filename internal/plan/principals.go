package plan

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// Principals gives a SID of the source's ACLs the SID of the same principal on the target (ACLTranslated), for clone
// to write and diff to compare. A SID of the source's domain names an object of the domain: a built-in one (a RID
// below 1000: Domain Admins, the Administrator) is the target's of the same RID; any other is the target object at
// the DN of the source's, which the clone keeps. Every other SID (Everyone, Authenticated Users, BUILTIN\..., a
// trusted domain's principal) is the same everywhere and passes as it is.
type Principals struct {
	src, dst  directory.Directory
	root      string
	srcDomain string
	dstDomain string
	plan      *Plan

	mu    sync.Mutex
	known map[string]principal
}

// principal is what a source SID became on the target: its SID there, or why there is none.
type principal struct{ sid, why string }

// The reasons a source SID has no principal on the target, which the ACEs naming it are left out for.
const (
	WhyNoSourcePrincipal = "names a SID no object of the source has (a deleted principal's; from a dump, one outside it)"
	WhyNoTargetPrincipal = "names a principal the target lacks (not cloned)"
)

// Principals reads both domains' SIDs. A nil dst (a dry-run, whose target holds no SIDs) passes every SID as it is.
func (p *Plan) Principals(ctx context.Context, dst directory.Directory) (*Principals, error) {
	d := p.job.Profile.Descriptors
	if d == nil {
		return nil, fmt.Errorf("the %s profile has no ACLs clone can copy", p.job.Profile.Name)
	}
	out := &Principals{src: p.src, dst: dst, root: p.Root, plan: p, known: map[string]principal{}}
	if dst == nil {
		return out, nil
	}
	var err error
	if out.srcDomain, err = d.Domain(ctx, p.src, p.Root); err != nil {
		return nil, fmt.Errorf("the source's domain: %w", err)
	}
	if out.dstDomain, err = d.Domain(ctx, dst, p.Root); err != nil {
		return nil, fmt.Errorf("the target's domain: %w", err)
	}
	return out, nil
}

// Target is the target's SID of sid, a SID of the source; "" and why when the target has no such principal.
func (t *Principals) Target(ctx context.Context, sid string) (string, string, error) {
	if t.dst == nil || !strings.HasPrefix(sid, t.srcDomain+"-") {
		return sid, "", nil
	}
	rid := sid[len(t.srcDomain)+1:]
	d := t.plan.job.Profile.Descriptors
	if d.WellKnown(rid) {
		return t.dstDomain + "-" + rid, "", nil
	}
	t.mu.Lock()
	p, ok := t.known[sid]
	t.mu.Unlock()
	if ok {
		return p.sid, p.why, nil
	}
	p, err := t.resolve(ctx, sid)
	if err != nil {
		return "", "", err
	}
	t.mu.Lock()
	t.known[sid] = p
	t.mu.Unlock()
	return p.sid, p.why, nil
}

func (t *Principals) resolve(ctx context.Context, sid string) (principal, error) {
	d := t.plan.job.Profile.Descriptors
	filter, err := d.Filter(sid)
	if err != nil {
		return principal{}, err
	}
	var at string
	if err := t.src.Walk(ctx, t.root, filter, []string{d.SIDAttr()}, func(e directory.Entry) error {
		at = e.DN
		return nil
	}); err != nil {
		return principal{}, err
	}
	if at == "" {
		return principal{why: WhyNoSourcePrincipal}, nil
	}
	e, err := t.dst.Get(ctx, at, []string{d.SIDAttr()})
	if err != nil {
		return principal{}, err
	}
	if e == nil || d.SID(*e) == "" {
		return principal{why: WhyNoTargetPrincipal}, nil
	}
	return principal{sid: d.SID(*e)}, nil
}

// Descriptor reads the security descriptor of the source object at dn; "" when it has none (a dump taken without
// them, or an account that may not read them).
func (t *Principals) Descriptor(ctx context.Context, dn string) (string, error) {
	attr := t.plan.job.Profile.Descriptors.Attr()
	e, err := t.src.Get(ctx, dn, []string{attr})
	if err != nil || e == nil {
		return "", err
	}
	return first(e.Values(attr)), nil
}

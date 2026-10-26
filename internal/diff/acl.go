package diff

import (
	"context"
	"fmt"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/plan"
)

// sdAttr is the attribute of an object's security descriptor.
const sdAttr = "nTSecurityDescriptor"

// aclTexts replaces each side's security descriptor with what of it the clone gives (profile.Descriptors.Parts): its
// owner, group and protected flag as one value, each explicit ACE as another, so a difference names the ACEs that
// differ. The inherited ACEs are each server's, computed from the object's parents. The order of the ACEs is not
// compared. With ACLTranslated the source's is first what clone writes (Principals): the target's SIDs, and without
// the ACEs whose trustee the target lacks, which are counted as not compared, as clone leaves them out.
func (r *runner) aclTexts(want, got directory.Entry) (directory.Entry, directory.Entry) {
	if r.job.ACL == plan.ACLNone {
		return want, got
	}
	return r.descriptorTexts(want, got, sdAttr, r.job.ACL == plan.ACLTranslated)
}

// descriptorTexts is aclTexts for any attribute whose value is a descriptor (attr): the ACL, or a value naming
// principals (plan.Job.SDValues, clone writes them translated). translate gives the source's value the target's SIDs
// first.
func (r *runner) descriptorTexts(want, got directory.Entry, attr string, translate bool) (directory.Entry, directory.Entry) {
	d := r.job.Profile.Descriptors
	if d == nil {
		return want, got
	}
	wantName, wantRaw := sdValue(want, attr)
	gotName, gotRaw := sdValue(got, attr)
	if translate && wantRaw != "" {
		out, dropped, err := d.Rewrite(wantRaw, gotRaw, r.translate(r.ctx))
		if err != nil {
			out = ""
			r.aclFailed(want.DN, attr, err)
		}
		wantRaw = out
		for _, sid := range dropped {
			why := r.whyDropped(sid)
			r.mu.Lock()
			r.sum.ACEsNotCompared[why]++
			r.mu.Unlock()
		}
	}
	return withParts(want, wantName, wantRaw, d.Parts), withParts(got, gotName, gotRaw, d.Parts)
}

// translate is Principals.Target as ExplicitOnly takes it; why a SID has no principal is told again by whyDropped,
// from the same cache.
func (r *runner) translate(ctx context.Context) func(string) (string, error) {
	return func(sid string) (string, error) {
		to, _, err := r.principals.Target(ctx, sid)
		return to, err
	}
}

func (r *runner) whyDropped(sid string) string {
	_, why, err := r.principals.Target(r.ctx, sid)
	if err != nil || why == "" {
		return plan.WhyNoTargetPrincipal
	}
	return why
}

// aclFailed keeps the first error translating a descriptor, which Run returns: compareEntry has no error to return.
func (r *runner) aclFailed(dn, attr string, err error) {
	r.primaryMu.Lock()
	defer r.primaryMu.Unlock()
	if r.aclErr == nil {
		r.aclErr = fmt.Errorf("%s: the source's %s: %w", dn, attr, err)
	}
}

func sdValue(e directory.Entry, attr string) (string, string) {
	for n, v := range e.Attrs {
		if strings.EqualFold(n, attr) && len(v) > 0 {
			return n, v[0]
		}
	}
	return "", ""
}

func withParts(e directory.Entry, name, raw string, parts func(string) ([]string, error)) directory.Entry {
	if name == "" {
		return e
	}
	out := directory.Entry{DN: e.DN, Attrs: make(map[string][]string, len(e.Attrs))}
	for n, v := range e.Attrs {
		out.Attrs[n] = v
	}
	if raw == "" {
		delete(out.Attrs, name)
		return out
	}
	p, err := parts(raw)
	if err != nil {
		p = []string{fmt.Sprintf("(unreadable: %v)", err)}
	}
	out.Attrs[name] = p
	return out
}

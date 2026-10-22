package app

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/lab"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// LikeSource returns the lab settings for a lab like the source: for AD the same domain (name, NetBIOS name, SID,
// GUID), so a native import can keep the source's objectSid and objectGUID; for a generic server an OpenLDAP lab
// with the source's naming context as its suffix.
func (s *Session) LikeSource(ctx context.Context) (lab.Settings, error) {
	if s.Job.Profile.Native == nil {
		root, err := plan.Root(ctx, s.Src, s.Job)
		if err != nil {
			return lab.Settings{}, err
		}
		return lab.Settings{Profile: lab.ProfileLDAP, Domain: root}, nil
	}
	d, err := s.domain(ctx)
	if err != nil {
		return lab.Settings{}, err
	}
	return lab.Settings{Profile: lab.ProfileAD, Domain: d.Realm, NetBIOS: d.NetBIOS, DomainSID: d.SID, DomainGUID: d.GUID}, nil
}

func (s *Session) domain(ctx context.Context) (profile.Domain, error) {
	native := s.Job.Profile.Native
	if native == nil {
		return profile.Domain{}, fmt.Errorf("a native import needs an AD (Samba) source; this source was detected as %q", s.Job.Profile.Name)
	}
	root, err := plan.Root(ctx, s.Src, s.Job)
	if err != nil {
		return profile.Domain{}, err
	}
	d, err := native.Domain(ctx, s.Src, root)
	if err != nil {
		return profile.Domain{}, fmt.Errorf("source: %w", err)
	}
	return d, nil
}

// Native imports into the lab's Samba keeping the source's objectGUID and objectSid, which cannot be given over
// LDAP. Samba only; it uses internals that are not a supported usage. It does not connect to the target over LDAP.
// The lab is stopped during the import and resumed afterwards, also when the import fails or is interrupted.
func (s *Session) Native(ctx context.Context, l *lab.Lab, opts lab.NativeOptions, out io.Writer) (report *clone.Report, err error) {
	if s.Job.ConfigurationRefs == plan.ConfigurationRefsClone {
		// The import writes the domain partition of the lab's database; the configuration partition is not tried.
		return nil, fmt.Errorf("[scope] configuration_refs = %q is not supported by clone -native, which imports the domain partition only", plan.ConfigurationRefsClone)
	}
	src, err := s.domain(ctx)
	if err != nil {
		return nil, err
	}
	password, err := s.secrets.UserPassword()
	if err != nil {
		return nil, err
	}
	// Asked before the lab is stopped: a No leaves it as it was.
	if s.Confirm != nil {
		if err := s.ask(ctx, "clone stops the lab and adds and updates entries under base_dn in its database ([target.lab] native = true)", "the lab "+l.Name()+" (Samba's database, written directly)"); err != nil {
			return nil, err
		}
	}
	n, err := l.OpenNative(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := n.Close(ctx); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if err := checkSameDomain(n.Info, src); err != nil {
		return nil, err
	}
	if s.Cfg.Mapping.Mode == config.MappingFile {
		fmt.Fprintf(s.Warn, "note: a native import keeps the identifiers, so no mapping (%s) is recorded; diff matches them directly\n", s.Cfg.Mapping.File)
	}
	// One worker: the helper handles one request at a time anyway.
	report, err = clone.Run(ctx, s.Src, n, s.Job, clone.Options{UserPassword: password, Workers: 1, Native: true, Progress: s.Progress}, out)
	if err != nil {
		return report, err
	}
	if opts.ACL {
		if err := s.nativeACLs(ctx, n, src.Root, out); err != nil {
			return report, err
		}
	}
	res, err := n.Finish(ctx)
	if err != nil {
		return report, fmt.Errorf("post-import cleanup (RID update, dbcheck) failed: %w", err)
	}
	fmt.Fprintf(out, "native: %s\n", res.Summary())
	return report, nil
}

// checkSameDomain verifies that the lab's domain is the source's (root DN, SID, GUID).
// Otherwise the imported objectSid would not belong to this domain.
func checkSameDomain(info lab.NativeInfo, src profile.Domain) error {
	var diffs []string
	if !dn.Equal(info.Base, src.Root) {
		diffs = append(diffs, fmt.Sprintf("domain root DN: lab %s / source %s", info.Base, src.Root))
	}
	if !strings.EqualFold(info.DomainSID, src.SID) {
		diffs = append(diffs, fmt.Sprintf("domain SID: lab %s / source %s", info.DomainSID, src.SID))
	}
	if !strings.EqualFold(info.DomainGUID, src.GUID) {
		diffs = append(diffs, fmt.Sprintf("domain GUID: lab %s / source %s", info.DomainGUID, src.GUID))
	}
	if len(diffs) > 0 {
		return fmt.Errorf("the lab's domain differs from the source's (%s). Create a lab with the same domain as the source by running lab reset, then lab up --config <config file>", strings.Join(diffs, ", "))
	}
	return nil
}

// sdAttr is the attribute of an object's security descriptor.
const sdAttr = "nTSecurityDescriptor"

// nativeACLs gives the lab's objects the source's owner, group and DACL ([target.lab] acl): the domain root and the
// containers above base_dn first, then every object of the lab under base_dn. Samba keeps what is written and
// computes the inherited ACEs from each object's parents, so once the parents above are the source's too, the
// descriptors are the source's byte for byte (measured on 4.19.5). The objects outside base_dn a reference or a
// membership brought (referenced objects, groups holding entries) keep the lab's.
func (s *Session) nativeACLs(ctx context.Context, n directory.Directory, root string, out io.Writer) error {
	written, above := 0, 0
	write := func(e directory.Entry) error {
		values := e.Values(sdAttr)
		if len(values) == 0 {
			return nil
		}
		cur, err := n.Get(ctx, e.DN, []string{"objectClass"})
		if err != nil || cur == nil {
			return err // not cloned (of no kind): nothing to give
		}
		if err := n.Replace(ctx, e.DN, map[string][]string{sdAttr: values}); err != nil {
			return fmt.Errorf("%s: the source's %s: %w", e.DN, sdAttr, err)
		}
		written++
		return nil
	}
	parents, seen := []string{root}, map[string]bool{}
	for _, b := range s.Job.BaseDNs {
		for _, a := range reverseDNs(dn.Ancestors(b, root)) {
			if !seen[dn.Normalize(a)] {
				seen[dn.Normalize(a)] = true
				parents = append(parents, a)
			}
		}
	}
	for _, d := range parents {
		e, err := s.Src.Get(ctx, d, []string{sdAttr})
		if err != nil {
			return err
		}
		if e != nil {
			before := written
			if err := write(*e); err != nil {
				return err
			}
			above += written - before
		}
	}
	if err := plan.WalkBases(ctx, s.Src, s.Job.BaseDNs, "(objectClass=*)", []string{sdAttr}, write); err != nil {
		return err
	}
	if written == 0 {
		fmt.Fprintf(s.Warn, "warning: the source gave no %s (a dump taken before ACLs were carried, or an account that may not read them): the lab keeps its own ACLs\n", sdAttr)
		return nil
	}
	fmt.Fprintf(out, "native: ACLs: the source's owner, group and DACL on %d objects (%d of them above base_dn)\n", written, above)
	return nil
}

func reverseDNs(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[len(in)-1-i] = v
	}
	return out
}

package app

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/config"
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
		if err := s.ask(ctx, "clone -native stops the lab and adds and updates entries under base_dn in its database", "the lab "+l.Name()+" (Samba's database, written directly)"); err != nil {
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
		return fmt.Errorf("the lab's domain differs from the source's (%s). Create a lab with the same domain as the source by running lab reset, then lab up --like-source <config file>", strings.Join(diffs, ", "))
	}
	return nil
}

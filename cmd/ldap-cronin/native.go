package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/adguid"
	"github.com/wadahiro/ldap-cronin/internal/attrs"
	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/lab"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/prompt"
)

// domainIdentity returns the objectSid and objectGUID (text form) of the domain root.
func domainIdentity(d directory.Directory, baseDN string) (sid, guid string, err error) {
	root := dn.DomainRoot(baseDN)
	e, err := d.Get(root, []string{plan.SIDAttr, plan.GUIDAttr})
	if err != nil {
		return "", "", fmt.Errorf("cannot read domain root %s: %w", root, err)
	}
	if e == nil {
		return "", "", fmt.Errorf("domain root %s not found", root)
	}
	rawSID, rawGUID := first(e.Values(plan.SIDAttr)), first(e.Values(plan.GUIDAttr))
	if rawSID == "" || rawGUID == "" {
		return "", "", fmt.Errorf("cannot read objectSid and objectGUID from domain root %s", root)
	}
	if sid, err = adguid.SIDText([]byte(rawSID)); err != nil {
		return "", "", err
	}
	if guid, err = adguid.GUIDText([]byte(rawGUID)); err != nil {
		return "", "", err
	}
	return sid, guid, nil
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// realmOf builds the domain name (a.b) from the domain root DN (DC=a,DC=b).
func realmOf(root string) string {
	var labels []string
	for _, rdn := range dn.Split(root) {
		if v, ok := strings.CutPrefix(strings.ToLower(rdn), "dc="); ok {
			labels = append(labels, v)
		}
	}
	return strings.Join(labels, ".")
}

// netbiosOf reads the domain's NetBIOS name from the partition's crossRef. Empty if it cannot be read.
func netbiosOf(d directory.Directory, root string) string {
	rootDSE, err := d.Get("", []string{"configurationNamingContext"})
	if err != nil || rootDSE == nil || first(rootDSE.Values("configurationNamingContext")) == "" {
		return ""
	}
	partitions := "CN=Partitions," + first(rootDSE.Values("configurationNamingContext"))
	found := ""
	_ = d.Walk(partitions, "(&(objectClass=crossRef)(nCName="+root+"))", []string{"nETBIOSName"}, func(e directory.Entry) error {
		if found == "" {
			found = first(e.Values("nETBIOSName"))
		}
		return nil
	})
	return found
}

// likeSource connects to the source AD and returns the settings for creating a lab with the same domain (name, NetBIOS name, SID, GUID).
func likeSource(cfgPath string) (lab.Settings, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return lab.Settings{}, err
	}
	pw, err := prompt.Password("source bind password", envSourcePassword, false)
	if err != nil {
		return lab.Settings{}, err
	}
	src, err := dial(cfg.Source, pw, sourceConnections)
	if err != nil {
		return lab.Settings{}, err
	}
	defer src.Close()
	sid, guid, err := domainIdentity(src, cfg.Clone.BaseDN)
	if err != nil {
		return lab.Settings{}, fmt.Errorf("source: %w", err)
	}
	root := dn.DomainRoot(cfg.Clone.BaseDN)
	return lab.Settings{Realm: realmOf(root), NetBIOS: netbiosOf(src, root), DomainSID: sid, DomainGUID: guid}, nil
}

// cloneNative imports into the lab's Samba keeping the source's objectGUID and objectSid (which cannot be specified over LDAP).
// Samba only; it uses internals that are not a supported usage. It does not connect to the target AD.
func cloneNative(cfg *config.Config, opt plan.Options, src directory.Directory, labFlags labCommon, out, errW io.Writer) (report *clone.Report, err error) {
	userPw, err := prompt.Password("fixed password for cloned users", envUserPassword, true)
	if err != nil {
		return nil, err
	}
	srcSID, srcGUID, err := domainIdentity(src, cfg.Clone.BaseDN)
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	l, err := newLab(labFlags, out, errW)
	if err != nil {
		return nil, err
	}
	n, err := l.OpenNative()
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := n.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if err := checkSameDomain(n.Info, dn.DomainRoot(cfg.Clone.BaseDN), srcSID, srcGUID); err != nil {
		return nil, err
	}
	if cfg.State.File != "" {
		fmt.Fprintf(errW, "note: native import keeps objectGUID identical, so no GUID mapping (%s) is created. diff matches GUIDs directly\n", cfg.State.File)
	}
	opt.KeepIdentity = true
	report, err = clone.Run(src, n, clone.Options{Plan: opt, UserPassword: userPw, Workers: 1}, out)
	if err != nil {
		return report, err
	}
	res, ferr := n.Finish()
	if ferr != nil {
		return report, fmt.Errorf("post-import cleanup (RID update, dbcheck) failed: %w", ferr)
	}
	fmt.Fprintf(out, "native: %s\n", res.Summary())
	return report, nil
}

// checkSameDomain verifies that the lab's domain is the same as the source's (base DN, SID, GUID).
// Otherwise the imported objectSid would not belong to this domain.
func checkSameDomain(info lab.NativeInfo, srcRoot, srcSID, srcGUID string) error {
	var diffs []string
	if !dn.Equal(info.Base, srcRoot) {
		diffs = append(diffs, fmt.Sprintf("domain root DN: lab %s / source %s", info.Base, srcRoot))
	}
	if !strings.EqualFold(info.DomainSID, srcSID) {
		diffs = append(diffs, fmt.Sprintf("domain SID: lab %s / source %s", info.DomainSID, srcSID))
	}
	if !strings.EqualFold(info.DomainGUID, srcGUID) {
		diffs = append(diffs, fmt.Sprintf("domain GUID: lab %s / source %s", info.DomainGUID, srcGUID))
	}
	if len(diffs) > 0 {
		return fmt.Errorf("the lab's domain differs from the source's (%s). Create a lab with the same domain as the source by running lab reset, then lab up --like-source <config file>", strings.Join(diffs, ", "))
	}
	return nil
}

// identityPreserved checks whether the target object has the same objectGUID as the source.
// It does not decide from the domain GUID matching (even a lab populated by an LDAP clone can have a matching domain GUID).
// It checks the base_dn object, and if that is not an OU (a container that already exists in the lab, such as CN=Users), checks the first object under it.
// If it cannot decide, it returns the reason.
func identityPreserved(src, dst directory.Directory, baseDN string) (same bool, reason string, err error) {
	probe, err := src.Get(baseDN, []string{"objectClass", plan.GUIDAttr})
	if err != nil {
		return false, "", err
	}
	if probe == nil {
		return false, "base_dn does not exist in the source", nil
	}
	if !hasClass(probe, "organizationalUnit") {
		probe = nil
		stop := errors.New("found")
		for _, kind := range attrs.Kinds {
			werr := src.Walk(baseDN, plan.DefaultFilters[kind], []string{"objectClass", plan.GUIDAttr}, func(e directory.Entry) error {
				if !strings.EqualFold(e.DN, baseDN) {
					c := e
					probe = &c
					return stop
				}
				return nil
			})
			if werr != nil && !errors.Is(werr, stop) {
				return false, "", werr
			}
			if probe != nil {
				break
			}
		}
		if probe == nil {
			return false, "no object to compare", nil
		}
	}
	want := first(probe.Values(plan.GUIDAttr))
	if want == "" {
		return false, "cannot read the source's objectGUID", nil
	}
	got, err := dst.Get(probe.DN, []string{plan.GUIDAttr})
	if err != nil {
		return false, "", err
	}
	if got == nil {
		return false, "target has no " + probe.DN, nil
	}
	if first(got.Values(plan.GUIDAttr)) != want {
		return false, probe.DN + " has a different objectGUID in the source and the target", nil
	}
	return true, "", nil
}

func hasClass(e *directory.Entry, class string) bool {
	for _, c := range e.Values("objectClass") {
		if strings.EqualFold(c, class) {
			return true
		}
	}
	return false
}

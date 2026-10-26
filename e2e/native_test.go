//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/ad"
	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/dump"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/lab"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// Samba-only native import: create a lab with the same domain SID and GUID as the source, and import including objectGUID and objectSid.
// The source is the lab's sample-loaded clone source; the import target is a lab with a different prefix (created with settings equivalent to --like-source).
func TestNativeImportKeepsObjectGUIDAndObjectSid(t *testing.T) {
	image := os.Getenv("E2E_LAB_IMAGE")
	if image == "" {
		t.Skip("E2E_LAB_IMAGE is not set (tests/e2e.sh sets it)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	host := env("E2E_LAB_HOST", "localhost")
	const realm, password, fixed = "native-e2e.test", "Adm1n-Passw0rd!", "Fixed-Passw0rd!"
	base := lab.BaseDN(realm)
	cloneBase := "OU=IDM," + base
	nano := time.Now().UnixNano() % 1_000_000
	var out, errw bytes.Buffer
	newLab := func(prefix string) *lab.Lab {
		return &lab.Lab{
			D: lab.ExecDocker{}, Out: &out, Err: &errw, Prompt: noPrompt{}, Prefix: prefix, Version: "e2e",
			Dirs: lab.Dirs{State: t.TempDir(), Snapshots: t.TempDir()}, Sleep: time.Sleep, Now: time.Now,
			Getenv:   func(string) string { return "" },
			FreePort: func() (int, error) { return freePort(t), nil },
		}
	}
	srcLab, dstLab := newLab(fmt.Sprintf("natsrc%d", nano)), newLab(fmt.Sprintf("natdst%d", nano))
	// clone creates the lab with the LDAPS port of [target] url; its LDAP port must not be the e2e Samba's either.
	dstLDAP := freePort(t)
	dstLab.Getenv = func(k string) string {
		if k == "AD_LDAP_PORT" {
			return strconv.Itoa(dstLDAP)
		}
		return ""
	}
	for _, l := range []*lab.Lab{srcLab, dstLab} {
		l := l
		t.Cleanup(func() { _ = l.Reset(context.Background(), lab.ResetOptions{Yes: true, Snapshots: true}) })
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%v\n%s", err, errw.String())
		}
	}
	dialAs := func(port int, bindDN, pw string) (*ldapdir.Client, error) {
		return ldapdir.Dial(ldapdir.ConnConfig{
			URL: fmt.Sprintf("ldaps://%s:%d", host, port), BindDN: bindDN, Password: pw, InsecureSkipVerify: true,
		}, 4)
	}
	admin := "CN=Administrator,CN=Users," + base

	srcLDAPS, dstLDAPS := freePort(t), freePort(t)
	must(srcLab.Up(context.Background(), lab.UpOptions{Image: image, Flags: lab.Settings{Domain: realm, AdminPassword: password, LDAPPort: freePort(t), LDAPSPort: freePort(t)},
		WithSource: true, SourceLDAP: freePort(t), SourceLDAPS: srcLDAPS}))
	src, err := dialAs(srcLDAPS, admin, password)
	must(err)
	defer src.Close()

	// What only the system may write (over LDAP the server refuses them), given to a user of the source from inside
	// its container: the lab must carry them to the import ([target.lab] server_attributes defaults to "source").
	serverAttrs := map[string]string{"lastLogonTimestamp": "133000000000000000", "lastLogon": "133200000000000000", "logonCount": "7",
		"lockoutTime": "133100000000000000", "badPwdCount": "3", "whenCreated": "20100102030405.0Z"}
	const withServerAttrs = "CN=Bob Staff,OU=Tokyo,OU=Users,OU=IDM,"
	const bobLeftover = "CN=Bob Staff\\0ACNF:0f0e0d0c-0b0a-0908-0706-050403020100,OU=Tokyo,OU=Users,OU=IDM,"
	setScript := "import ldb\nfrom samba.samdb import SamDB\nfrom samba.auth import system_session\nfrom samba.param import LoadParm\n" +
		"lp = LoadParm(); lp.load('/etc/samba/smb.conf')\ndb = SamDB(url='/var/lib/samba/private/sam.ldb', session_info=system_session(), lp=lp)\n" +
		"m = ldb.Message(ldb.Dn(db, '" + withServerAttrs + base + "'))\n"
	for k, v := range serverAttrs {
		setScript += fmt.Sprintf("m[%q] = ldb.MessageElement([%q], ldb.FLAG_MOD_REPLACE, %q)\n", k, v, k)
	}
	// SIDs are binary: packed from their text.
	setScript += "from samba.ndr import ndr_pack\nfrom samba.dcerpc import security\n" +
		"for name in ('sIDHistory', 'mS-DS-CreatorSID'):\n" +
		"    m[name] = ldb.MessageElement([ndr_pack(security.dom_sid('S-1-5-21-1111111111-2222222222-3333333333-1234'))], ldb.FLAG_MOD_REPLACE, name)\n" +
		"db.modify(m)\n" +
		// Credentials ([attributes] credentials = "copy"): a private key, and a resource-based delegation, which
		// Samba lets only the system write and the import, writing as the system, carries with the SID it names.
		"m = ldb.Message(ldb.Dn(db, '" + withServerAttrs + base + "'))\n" +
		"m['userPKCS12'] = ldb.MessageElement([b'not a real key'], ldb.FLAG_MOD_REPLACE, 'userPKCS12')\n" +
		"rbcd = security.descriptor.from_sddl('O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;' + str(db.get_domain_sid()) + '-1234)', security.dom_sid(db.get_domain_sid()))\n" +
		"m['msDS-AllowedToActOnBehalfOfOtherIdentity'] = ldb.MessageElement([ndr_pack(rbcd)], ldb.FLAG_MOD_REPLACE, 'msDS-AllowedToActOnBehalfOfOtherIdentity')\n" +
		"db.modify(m)\n" +
		// ACEs of its own, on the user and on the domain root (a delegation every OU inherits), which the lab has
		// not: only the copy of the ACLs, the root's among them, makes the descriptors equal.
		"from samba.ndr import ndr_unpack\n" +
		"for dn, sddl in (('" + withServerAttrs + base + "', 'D:(A;CI;RP;;;AU)(D;;WP;;;WD)'), ('" + base + "', 'D:(A;CI;LCRP;;;S-1-5-32-548)')):\n" +
		"    r = db.search(dn, scope=ldb.SCOPE_BASE, attrs=['nTSecurityDescriptor'], controls=['sd_flags:1:7'])\n" +
		"    sd = ndr_unpack(security.descriptor, r[0]['nTSecurityDescriptor'][0])\n" +
		"    for ace in security.descriptor.from_sddl(sddl, security.dom_sid('S-1-5-21-0-0-0')).dacl.aces:\n" +
		"        sd.dacl_add(ace)\n" +
		"    m = ldb.Message(ldb.Dn(db, dn))\n" +
		"    m['nTSecurityDescriptor'] = ldb.MessageElement([ndr_pack(sd)], ldb.FLAG_MOD_REPLACE, 'nTSecurityDescriptor')\n" +
		"    db.modify(m, controls=['sd_flags:1:7'])\n"
	// A replication-conflict leftover of Bob, keeping his userPrincipalName as AD keeps it: samldb refuses the value
	// on a second object even to the system, so it is written to the partition's file without the modules. The
	// import creates the leftover without it.
	setScript += "db.add({'dn': r'" + bobLeftover + base + "', 'objectClass': 'user', 'sAMAccountName': '$DUPLICATE-1f4'})\n" + rawDomainPartition +
		"m = ldb.Message(ldb.Dn(raw, r'" + bobLeftover + base + "'))\n" +
		"m['userPrincipalName'] = ldb.MessageElement(['bob@" + realm + "'], ldb.FLAG_MOD_REPLACE, 'userPrincipalName')\n" +
		"raw.modify(m)\n"
	if out, err := exec.Command("docker", "exec", srcLab.Prefix+"-ad-src", "python3", "-c", setScript).CombinedOutput(); err != nil {
		t.Fatalf("setting the server attributes on the source: %v\n%s", err, out)
	}

	root, err := src.Get(context.Background(), base, []string{"objectSid", "objectGUID"})
	must(err)
	srcSID, err := ad.SIDText([]byte(root.Values("objectSid")[0]))
	must(err)
	srcGUID, err := ad.GUIDText([]byte(root.Values("objectGUID")[0]))
	must(err)

	// The lab is the target of the config ([target.lab] native = true): before lab up --config made it, check says
	// to make it and clone refuses; lab up --config makes it like the source (the same domain SID and GUID), and
	// clone imports into it.
	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nurl = \"ldaps://%s:%d\"\nbind_dn = %q\ninsecure_skip_verify = true\n"+
		"[target]\nurl = \"ldaps://%s:%d\"\nbind_dn = %q\ninsecure_skip_verify = true\n"+
		"[target.lab]\nprefix = %q\nimage = %q\nnative = true\nfast_password = true\nacl = \"source\"\n"+
		"[scope]\nbase_dn = %q\n[attributes]\nmode = \"allowlist\"\ncredentials = \"copy\"\n"+
		"extra_include = [\"carLicense\", \"seeAlso\", \"userPKCS12\", \"msDS-AllowedToActOnBehalfOfOtherIdentity\"]\n[mask]\nattributes = [\"mail\"]\n",
		host, srcLDAPS, admin, host, dstLDAPS, admin, dstLab.Prefix, image, cloneBase)))
	must(err)
	pw := func() (string, error) { return password, nil }
	s, err := app.Open(context.Background(), cfg, app.Secrets{SourceBind: pw, TargetBind: pw, UserPassword: func() (string, error) { return fixed, nil }}, app.LDAP, &bytes.Buffer{})
	must(err)
	defer s.Close()
	s.ConfigPath = "c.toml"
	var report bytes.Buffer
	code, err := s.Check(context.Background(), app.CheckOptions{Config: "c.toml", Lab: dstLab}, &report)
	must(err)
	if code != app.CheckBlocked || !strings.Contains(report.String(), "does not exist yet: ldap-cronin lab up --config c.toml creates it like the source") ||
		!strings.Contains(report.String(), "make the lab: ldap-cronin lab up --config c.toml") {
		t.Fatalf("check before the lab exists (exit %d):\n%s", code, report.String())
	}
	var cloned bytes.Buffer
	if _, err := s.CloneLab(context.Background(), dstLab, &cloned, &cloned); err == nil || !strings.Contains(err.Error(), "lab up --config c.toml creates it") {
		t.Fatalf("clone before lab up --config: %v", err)
	}
	if err := s.LabUp(context.Background(), dstLab, lab.UpOptions{}, &cloned); err != nil {
		t.Fatalf("%v\n%s\n%s", err, cloned.String(), errw.String())
	}
	rep, err := s.CloneLab(context.Background(), dstLab, &cloned, &cloned)
	if err != nil {
		t.Fatalf("%v\n%s\n%s", err, cloned.String(), errw.String())
	}
	t.Logf("clone:\n%s", cloned.String())
	if rep.Added == 0 || !regexp.MustCompile(`fast_password: [1-9]\d* users got the NT hash directly`).MatchString(cloned.String()) {
		t.Fatalf("the lab is created and imported into, the passwords the fast way: %+v\n%s", rep, cloned.String())
	}
	if rep.Withheld["userPrincipalName"] != 1 {
		t.Fatalf("the leftover's userPrincipalName is withheld: %+v\n%s", rep.Withheld, cloned.String())
	}
	// The credentials are the source's, the delegation naming the same SID (the lab has the source's domain SID).
	creds := []string{"userPKCS12", "msDS-AllowedToActOnBehalfOfOtherIdentity"}
	held, err := src.Get(context.Background(), withServerAttrs+base, creds)
	must(err)
	imported, err := dialAs(dstLDAPS, admin, password)
	must(err)
	got, err := imported.Get(context.Background(), withServerAttrs+base, creds)
	must(err)
	left, err := imported.Get(context.Background(), bobLeftover+base, []string{"sAMAccountName", "userPrincipalName"})
	imported.Close()
	must(err)
	if left == nil || strings.Join(left.Values("sAMAccountName"), "") != "$DUPLICATE-1f4" || left.Values("userPrincipalName") != nil {
		t.Fatalf("the leftover in the lab: %+v", left)
	}
	for _, a := range creds {
		if len(held.Values(a)) != 1 || strings.Join(got.Values(a), "") != strings.Join(held.Values(a), "") {
			t.Fatalf("%s: the source holds %d values, the lab %d, equal %v", a, len(held.Values(a)), len(got.Values(a)),
				strings.Join(got.Values(a), "") == strings.Join(held.Values(a), ""))
		}
	}
	var compared bytes.Buffer
	if code, err := s.Diff(context.Background(), app.DiffOutput{}, &compared); err != nil || code != app.ExitSame ||
		!strings.Contains(compared.String(), "credentials copied from the source") {
		t.Fatalf("diff after the import (%d, %v):\n%s", code, err, compared.String())
	}
	report.Reset()
	if code, err := s.Check(context.Background(), app.CheckOptions{Config: "c.toml", Lab: dstLab}, &report); err != nil || code != app.CheckReady ||
		!strings.Contains(report.String(), "its database written directly") {
		t.Fatalf("check after the clone (exit %d, %v):\n%s", code, err, report.String())
	}

	importNative := func(opts lab.NativeOptions) (*clone.Report, lab.NativeFinish) {
		t.Helper()
		n, err := dstLab.OpenNative(context.Background(), opts)
		must(err)
		defer func() { must(n.Close(context.Background())) }()
		if n.Info.DomainSID != srcSID || !strings.EqualFold(n.Info.DomainGUID, srcGUID) {
			t.Fatalf("the lab must share the source's domain identity: %+v vs %s %s", n.Info, srcSID, srcGUID)
		}
		opt := planOptionsFor(t, cloneBase)
		rep, err := clone.Run(context.Background(), src, n, opt, clone.Options{UserPassword: fixed, Workers: 1, Native: true}, &bytes.Buffer{})
		must(err)
		res, err := n.Finish(context.Background())
		must(err)
		t.Logf("native: %s", res.Summary())
		return rep, res
	}

	dst, err := dialAs(dstLDAPS, admin, password)
	must(err)
	defer dst.Close()

	// objectGUID, objectSid and what the server keeps match for all objects ([target.lab] server_attributes defaults to "source").
	// nTSecurityDescriptor too, byte for byte ([target.lab] acl = "source"): the domain root's is the
	// source's as well, so the inherited ACEs are.
	names := []string{"objectGUID", "objectSid", "whenCreated", "lastLogonTimestamp", "lastLogon", "logonCount", "lockoutTime", "badPwdCount", "sIDHistory", "mS-DS-CreatorSID", "nTSecurityDescriptor"}
	checked := 0
	err = src.Walk(context.Background(), cloneBase, "(|(objectClass=user)(objectClass=group)(objectClass=organizationalUnit))", names, func(e directory.Entry) error {
		got, err := dst.Get(context.Background(), e.DN, names)
		if err != nil || got == nil {
			return fmt.Errorf("%s does not exist on the target: %v", e.DN, err)
		}
		for _, n := range names {
			if e.DN == withServerAttrs+base && n != "objectGUID" && n != "objectSid" && len(e.Values(n)) == 0 {
				return fmt.Errorf("the source lacks %s on %s: it was not set", n, e.DN)
			}
			if strings.Join(e.Values(n), ",") != strings.Join(got.Values(n), ",") {
				return fmt.Errorf("%s of %s does not match: %x / %x", n, e.DN, e.Values(n), got.Values(n))
			}
		}
		checked++
		return nil
	})
	must(err)
	if checked < 10 {
		t.Fatalf("only %d objects compared", checked)
	}

	// diff without a mapping reports no differences, including references (member/manager).
	opt := planOptionsFor(t, cloneBase)
	var diffs []diff.Difference
	sum, err := diff.Run(context.Background(), src, dst, opt, diff.Options{Workers: 4, Resolver: identity.ByIdentity(identity.ObjectGUID)}, func(d diff.Difference) { diffs = append(diffs, d) })
	must(err)
	if len(diffs) != 0 || !strings.Contains(sum.Matching, "preserved") {
		var b bytes.Buffer
		for _, d := range diffs {
			diff.Format(&b, d, diff.DefaultMaxValues)
		}
		t.Fatalf("diff after native import:\n%s", b.String())
	}

	// Login works with the fixed password.
	alice := "CN=Alice Admin,OU=Tokyo,OU=Users," + cloneBase
	login, err := dialAs(dstLDAPS, alice, fixed)
	if err != nil {
		t.Fatalf("login as alice: %v", err)
	}
	login.Close()

	// Every enabled user logs on with the fixed password, those given the NT hash directly too, and not with another.
	var enabled []string
	err = dst.Walk(context.Background(), cloneBase, "(&(objectCategory=person)(objectClass=user))", []string{"userAccountControl"}, func(e directory.Entry) error {
		var uac int
		if _, err := fmt.Sscan(strings.Join(e.Values("userAccountControl"), ""), &uac); err == nil && uac&2 == 0 {
			enabled = append(enabled, e.DN)
		}
		return nil
	})
	must(err)
	if len(enabled) < 2 {
		t.Fatalf("at least two enabled users are needed to see both ways of setting the password: %v", enabled)
	}
	for _, u := range enabled {
		c, err := dialAs(dstLDAPS, u, fixed)
		if err != nil {
			t.Fatalf("login as %s with the fixed password: %v", u, err)
		}
		c.Close()
	}
	if c, err := dialAs(dstLDAPS, enabled[len(enabled)-1], fixed+"x"); err == nil {
		c.Close()
		t.Fatal("another password must be refused")
	}

	// An import from a dump that stops midway keeps what it finished in the lab's journal: the next one skips it,
	// adds the rest and removes the journal. An OU of its own, which the imports above did not touch, and before the
	// lab creates an object of its own, whose RID the source's new objects could take.
	slice := "OU=Slice," + cloneBase
	must(src.Add(context.Background(), directory.Entry{DN: slice, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"Slice"}}}))
	for i := range 5 {
		must(src.Add(context.Background(), directory.Entry{DN: fmt.Sprintf("CN=Slice %d,%s", i, slice),
			Attrs: map[string][]string{"objectClass": {"user"}, "sAMAccountName": {fmt.Sprintf("slice%d", i)}}}))
	}
	var dumped bytes.Buffer
	_, err = dump.Write(context.Background(), src, profile.AD, dump.Options{BaseDNs: []string{slice}, Server: "ldaps://source", Version: "e2e"}, &dumped)
	must(err)
	dumpPath := filepath.Join(t.TempDir(), "slice.ldif")
	must(os.WriteFile(dumpPath, dumped.Bytes(), 0o600))
	sliceCfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nldif = %q\n"+
		"[target]\nurl = \"ldaps://%s:%d\"\nbind_dn = %q\ninsecure_skip_verify = true\n"+
		"[target.lab]\nprefix = %q\nimage = %q\nnative = true\n[scope]\nbase_dn = %q\n", dumpPath, host, dstLDAPS, admin, dstLab.Prefix, image, slice)))
	must(err)
	sliced, err := app.Open(context.Background(), sliceCfg, app.Secrets{SourceBind: pw, TargetBind: pw, UserPassword: func() (string, error) { return fixed, nil }}, app.LDAP, &bytes.Buffer{})
	must(err)
	defer sliced.Close()
	stopped, stop := context.WithCancel(context.Background())
	interrupt := &stopAfterAdds{left: 2, stop: stop}
	if _, err := sliced.CloneLab(stopped, dstLab, interrupt, interrupt); !errors.Is(err, context.Canceled) {
		t.Fatalf("the interrupted import: %v\n%s", err, interrupt.log.String())
	}
	journal := func() bool {
		return exec.Command("docker", "exec", dstLab.Name(), "test", "-f", "/var/lib/samba/ldap-cronin-journal").Run() == nil
	}
	if !journal() {
		t.Fatal("the interrupted import left no journal in the lab")
	}
	var resumed bytes.Buffer
	sliceRep, err := sliced.CloneLab(context.Background(), dstLab, &resumed, &resumed)
	if err != nil {
		t.Fatalf("%v\n%s", err, resumed.String())
	}
	if sliceRep.Resumed < 1 || sliceRep.Added != 3 || !strings.Contains(resumed.String(), "resuming: the lab's journal holds") || journal() {
		t.Fatalf("the resumed import: %+v, journal left %v\n%s", sliceRep, journal(), resumed.String())
	}
	// The imports stopped and restarted the lab.
	dst.Close()
	dst, err = dialAs(dstLDAPS, admin, password)
	must(err)

	// A user created over LDAP after the import does not collide with the imported RIDs.
	conn, err := ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", host, dstLDAPS), ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	must(err)
	defer conn.Close()
	must(conn.Bind(admin, password))
	fresh := "CN=Fresh,OU=Users," + cloneBase
	must(dst.Add(context.Background(), directory.Entry{DN: fresh, Attrs: map[string][]string{"objectClass": {"user"}, "cn": {"Fresh"}, "sAMAccountName": {"fresh"}}}))
	freshEntry, err := dst.Get(context.Background(), fresh, []string{"objectSid"})
	must(err)
	freshSID, err := ad.SIDText([]byte(freshEntry.Values("objectSid")[0]))
	must(err)
	_, freshRID, err := ad.SplitRID(freshSID)
	must(err)
	maxImported := 0
	err = src.Walk(context.Background(), cloneBase, "(objectSid=*)", []string{"objectSid"}, func(e directory.Entry) error {
		s, err := ad.SIDText([]byte(e.Values("objectSid")[0]))
		if err != nil {
			return err
		}
		if _, rid, err := ad.SplitRID(s); err == nil && rid > maxImported {
			maxImported = rid
		}
		return nil
	})
	must(err)
	if freshRID <= maxImported {
		t.Fatalf("a user created after the import must get a RID above the imported ones: %d <= %d", freshRID, maxImported)
	}
	must(conn.Del(ldap.NewDelRequest(fresh, nil)))

	// Re-running only updates the same objects and adds nothing. The lab is stopped and restored, so the connection is reopened.
	if again, _ := importNative(lab.NativeOptions{}); again.Added != 0 {
		t.Fatalf("a re-run must not add anything: %+v", again)
	}
	reconnect := func() {
		t.Helper()
		dst.Close()
		conn.Close()
		if dst, err = dialAs(dstLDAPS, admin, password); err != nil {
			t.Fatal(err)
		}
		if conn, err = ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", host, dstLDAPS), ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})); err != nil {
			t.Fatal(err)
		}
		must(conn.Bind(admin, password))
	}
	reconnect()

	// Even when renamed on the target, it is detected as RENAMED without a mapping.
	must(conn.ModifyDN(ldap.NewModifyDNRequest(alice, "CN=Alice Smith", true, "")))
	diffs = nil
	_, err = diff.Run(context.Background(), src, dst, opt, diff.Options{Workers: 4, Resolver: identity.ByIdentity(identity.ObjectGUID)}, func(d diff.Difference) { diffs = append(diffs, d) })
	must(err)
	renamed := false
	for _, d := range diffs {
		if d.Kind == diff.Renamed && dn.Equal(d.DN, alice) {
			renamed = true
		}
	}
	if !renamed {
		t.Fatalf("a rename on the target must be RENAMED without a mapping file: %+v", diffs)
	}

	// Restoring from a snapshot does not change objectGUID or objectSid.
	_, err = dstLab.Snapshot(context.Background(), lab.SnapshotOptions{Name: "native"})
	must(err)
	_, err = dstLab.RestoreWith(context.Background(), "native", lab.RestoreOptions{})
	must(err)
	reconnect()
	g1, err := dst.Get(context.Background(), strings.Replace(alice, "CN=Alice Admin", "CN=Alice Smith", 1), names)
	must(err)
	g2, err := src.Get(context.Background(), alice, names)
	must(err)
	if g1 == nil || strings.Join(g1.Values("objectGUID"), "") != strings.Join(g2.Values("objectGUID"), "") {
		t.Fatalf("restore must keep the objectGUID: %+v / %+v", g1, g2)
	}

}

// stopAfterAdds is a log that cancels the run once it has said it added left entries.
type stopAfterAdds struct {
	left int
	stop context.CancelFunc
	log  bytes.Buffer
}

func (w *stopAfterAdds) Write(p []byte) (int, error) {
	w.log.Write(p)
	if w.left > 0 && bytes.Contains(p, []byte("add    CN=Slice")) {
		if w.left--; w.left == 0 {
			w.stop()
		}
	}
	return len(p), nil
}

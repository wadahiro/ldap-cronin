//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/ad"
	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/lab"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
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
	must(srcLab.Up(context.Background(), lab.UpOptions{Image: image, Flags: lab.Settings{Realm: realm, AdminPassword: password, LDAPPort: freePort(t), LDAPSPort: freePort(t)},
		WithSource: true, SourceLDAP: freePort(t), SourceLDAPS: srcLDAPS}))
	src, err := dialAs(srcLDAPS, admin, password)
	must(err)
	defer src.Close()

	// Equivalent to --like-source: read the source domain's SID and GUID and create the lab with the same values.
	root, err := src.Get(context.Background(), base, []string{"objectSid", "objectGUID"})
	must(err)
	srcSID, err := ad.SIDText([]byte(root.Values("objectSid")[0]))
	must(err)
	srcGUID, err := ad.GUIDText([]byte(root.Values("objectGUID")[0]))
	must(err)
	must(dstLab.Up(context.Background(), lab.UpOptions{Image: image, Flags: lab.Settings{Realm: realm, AdminPassword: password,
		DomainSID: srcSID, DomainGUID: srcGUID, LDAPPort: freePort(t), LDAPSPort: dstLDAPS}}))

	importNative := func() *clone.Report {
		t.Helper()
		n, err := dstLab.OpenNative(context.Background())
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
		return rep
	}
	rep := importNative()
	if rep.Added == 0 {
		t.Fatalf("nothing imported: %+v", rep)
	}

	dst, err := dialAs(dstLDAPS, admin, password)
	must(err)
	defer dst.Close()

	// objectGUID and objectSid match for all objects.
	names := []string{"objectGUID", "objectSid"}
	checked := 0
	err = src.Walk(context.Background(), cloneBase, "(|(objectClass=user)(objectClass=group)(objectClass=organizationalUnit))", names, func(e directory.Entry) error {
		got, err := dst.Get(context.Background(), e.DN, names)
		if err != nil || got == nil {
			return fmt.Errorf("%s does not exist on the target: %v", e.DN, err)
		}
		for _, n := range names {
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
	if again := importNative(); again.Added != 0 {
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

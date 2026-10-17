//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/lab"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

const acmeSchema = `dn: cn=acme,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: acme
olcAttributeTypes: ( 1.3.6.1.4.1.99999.1.1 NAME 'acmeEmployeeCode' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.99999.2.1 NAME 'acmePerson' AUXILIARY MAY ( acmeEmployeeCode ) )
`

// The OpenLDAP lab with real docker: up with a deployment schema and the sample source -> clone (entryUUID kept)
// -> diff -> snapshot -> change -> restore -> another instance on another port -> a different suffix refused.
func TestOpenLDAPLabWithRealDocker(t *testing.T) {
	image := os.Getenv("E2E_LDAP_IMAGE")
	if image == "" {
		t.Skip("E2E_LDAP_IMAGE is not set (tests/e2e.sh builds it)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	ctx := context.Background()
	host := env("E2E_LAB_HOST", "localhost")
	const suffix, password = "dc=lab-e2e,dc=test", "Adm1n-Passw0rd!"
	admin := "cn=admin," + suffix
	dir := t.TempDir()
	schemaDir := t.TempDir()
	if err := os.WriteFile(schemaDir+"/10-acme.ldif", []byte(acmeSchema), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errw bytes.Buffer
	l := &lab.Lab{
		D: lab.ExecDocker{}, Out: &out, Err: &errw, Prompt: noPrompt{}, Version: "e2e",
		Prefix: fmt.Sprintf("labldap%d", time.Now().UnixNano()%1_000_000),
		Dirs:   lab.Dirs{State: dir, Snapshots: dir + "/snapshots"}, Sleep: time.Sleep, Now: time.Now,
		Getenv:   func(string) string { return "" },
		FreePort: func() (int, error) { return freePort(t), nil },
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%v\n%s%s", err, out.String(), errw.String())
		}
	}
	must(l.ChooseServer(ctx, lab.ProfileLDAP))
	t.Cleanup(func() { _ = l.Reset(context.Background(), lab.ResetOptions{Yes: true, Snapshots: true}) })

	ldaps, srcLDAPS := freePort(t), freePort(t)
	started := time.Now()
	must(l.Up(ctx, lab.UpOptions{
		Image: image, SchemaDir: schemaDir, WithSource: true, SourceLDAP: freePort(t), SourceLDAPS: srcLDAPS,
		Flags: lab.Settings{Domain: suffix, AdminPassword: password, LDAPPort: freePort(t), LDAPSPort: ldaps},
	}))
	t.Logf("up (lab and sample source): %.1fs", time.Since(started).Seconds())
	dial := func(port int) *ldapdir.Client {
		c, err := ldapdir.Dial(ldapdir.ConnConfig{URL: fmt.Sprintf("ldaps://%s:%d", host, port), BindDN: admin, Password: password, InsecureSkipVerify: true}, 4)
		must(err)
		t.Cleanup(c.Close)
		return c
	}
	src, target := dial(srcLDAPS), dial(ldaps)

	// The sample source is cloned into the lab as a user would, keeping entryUUID with the relax control.
	base := "ou=IDM," + suffix
	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nurl = \"ldaps://%s:%d\"\nbind_dn = %q\n[target]\nurl = \"ldaps://%s:%d\"\nbind_dn = %q\n[scope]\nbase_dn = %q\n",
		host, srcLDAPS, admin, host, ldaps, admin, base)))
	must(err)
	job, err := cfg.JobFor(profile.LDAP)
	must(err)
	rep, err := clone.Run(ctx, src, target, job, clone.Options{UserPassword: "Fixed-Passw0rd", Workers: 4, Preserve: true, Operational: true}, &bytes.Buffer{})
	must(err)
	if rep.Added < 10 || rep.WarningCount != 0 {
		t.Fatalf("clone of the sample data: %+v", rep)
	}
	var diffs []diff.Difference
	_, err = diff.Run(ctx, src, target, job, diff.Options{Workers: 4, Resolver: identity.ByIdentity(identity.EntryUUID)}, func(d diff.Difference) { diffs = append(diffs, d) })
	must(err)
	if len(diffs) != 0 {
		t.Fatalf("a fresh clone of the sample data must have no differences: %+v", diffs)
	}

	// The deployment schema from --schema-dir is in place.
	coded := "uid=coded," + suffix
	must(target.Add(ctx, directory.Entry{DN: coded, Attrs: map[string][]string{
		"objectClass": {"inetOrgPerson", "acmePerson"}, "uid": {"coded"}, "cn": {"coded"}, "sn": {"c"}, "acmeEmployeeCode": {"E1"},
	}}))
	alice := "uid=alice,ou=Tokyo,ou=People," + base
	uuidOf := func(d directory.Directory, dnStr string) string {
		t.Helper()
		e, err := d.Get(ctx, dnStr, []string{"entryUUID"})
		must(err)
		if e == nil {
			return ""
		}
		return e.Values("entryUUID")[0]
	}
	aliceUUID := uuidOf(target, alice)
	if aliceUUID == "" || aliceUUID != uuidOf(src, alice) {
		t.Fatal("alice must carry the source's entryUUID")
	}

	// Snapshot, change, restore.
	_, err = l.Snapshot(ctx, lab.SnapshotOptions{Name: "cloned"})
	must(err)
	target.Close()
	target = dial(ldaps)
	extra := "uid=later," + suffix
	must(target.Add(ctx, directory.Entry{DN: extra, Attrs: map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"later"}, "cn": {"later"}, "sn": {"l"}}}))
	_, err = l.Restore(ctx, "cloned")
	must(err)
	target.Close()
	target = dial(ldaps)
	if e, err := target.Get(ctx, extra, []string{"uid"}); err != nil || e != nil {
		t.Fatalf("the entry added after the snapshot must be gone: %v %v", e, err)
	}
	if uuidOf(target, alice) != aliceUUID || uuidOf(target, coded) == "" {
		t.Fatal("the restored data must be the snapshot's")
	}

	// Another instance on another port, from the same snapshot; it takes the snapshot's kind by itself.
	dev2 := *l
	dev2.Server, dev2.Instance = nil, "dev2"
	t.Cleanup(func() { _ = dev2.Reset(context.Background(), lab.ResetOptions{Yes: true}) })
	must(dev2.ChooseServer(ctx, ""))
	_, err = dev2.RestoreWith(ctx, "cloned", lab.RestoreOptions{AdminPassword: password})
	must(err)
	instances, err := l.Instances(ctx)
	must(err)
	dev2Port := 0
	for _, in := range instances {
		if in.Instance == "dev2" && in.Profile == lab.ProfileLDAP {
			dev2Port = in.LDAPS
		}
	}
	if dev2Port == 0 || dev2Port == ldaps {
		t.Fatalf("instances: %+v", instances)
	}
	if uuidOf(dial(dev2Port), alice) != aliceUUID {
		t.Fatal("the other instance must hold the same data")
	}

	// The existing volume belongs to another suffix: up refuses without touching it.
	err = l.Up(ctx, lab.UpOptions{Image: image, Flags: lab.Settings{Domain: "dc=other,dc=test", AdminPassword: password, LDAPPort: 1, LDAPSPort: ldaps}})
	if err == nil || !strings.Contains(err.Error(), "different settings") {
		t.Fatalf("a different suffix must be refused: %v", err)
	}
}

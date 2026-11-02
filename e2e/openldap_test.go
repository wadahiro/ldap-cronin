//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/dump"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
	"github.com/wadahiro/ldap-cronin/internal/ldifdir"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

const (
	olBase  = "dc=example,dc=org"
	olAdmin = "cn=admin," + olBase
	olPw    = "admin"
	olClone = "ou=IDM," + olBase
)

const olSeed = `dn: ou=IDM,dc=example,dc=org
objectClass: organizationalUnit
ou: IDM

dn: ou=People,ou=IDM,dc=example,dc=org
objectClass: organizationalUnit
ou: People

dn: ou=Groups,ou=IDM,dc=example,dc=org
objectClass: organizationalUnit
ou: Groups

dn: uid=alice,ou=People,ou=IDM,dc=example,dc=org
objectClass: inetOrgPerson
cn: Alice
sn: A
uid: alice
mail: alice@example.org
userPassword: secret-alice

dn: uid=bob,ou=People,ou=IDM,dc=example,dc=org
objectClass: inetOrgPerson
cn: Bob
sn: B
uid: bob
manager: uid=alice,ou=People,ou=IDM,dc=example,dc=org

dn: cn=Eng,ou=Groups,ou=IDM,dc=example,dc=org
objectClass: groupOfNames
cn: Eng
member: uid=alice,ou=People,ou=IDM,dc=example,dc=org
member: uid=bob,ou=People,ou=IDM,dc=example,dc=org

dn: cn=batch,ou=IDM,dc=example,dc=org
objectClass: applicationProcess
cn: batch

dn: cn=Devices,uid=alice,ou=People,ou=IDM,dc=example,dc=org
objectClass: groupOfNames
cn: Devices
member: uid=bob,ou=People,ou=IDM,dc=example,dc=org
`

// olACL grants cn=cloner manage (what the relax control needs) and cn=writer only write, ahead of the image's own
// rules. It is applied through the image's schema directory when the directory is created.
const olACL = `dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {1}to * by dn.exact="cn=cloner,dc=example,dc=org" manage by dn.exact="cn=writer,dc=example,dc=org" write by * break
`

// startOpenLDAP runs a throw-away OpenLDAP of our image (docker/ldap) and returns its host port. ldifs go into the
// image's /schema.d before the first start.
func startOpenLDAP(t *testing.T, image, name string, ldifs map[string]string) int {
	t.Helper()
	return startOpenLDAPAt(t, image, name, olBase, ldifs)
}

// startOpenLDAPAt is startOpenLDAP with the database suffix given; its admin is cn=admin,<suffix>.
func startOpenLDAPAt(t *testing.T, image, name, suffix string, ldifs map[string]string) int {
	t.Helper()
	port := freePort(t)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	out, err := exec.Command("docker", "create", "--name", name, "-p", fmt.Sprintf("%d:389", port),
		"-e", "LDAP_SUFFIX="+suffix, "-e", "LDAP_ADMIN_PASSWORD="+olPw, image).CombinedOutput()
	if err != nil {
		t.Fatalf("docker create: %v\n%s", err, out)
	}
	dir := t.TempDir()
	for file, content := range ldifs {
		if err := os.WriteFile(dir+"/"+file, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("docker", "cp", dir+"/.", name+":/schema.d/").CombinedOutput(); err != nil {
		t.Fatalf("docker cp: %v\n%s", err, out)
	}
	if out, err := exec.Command("docker", "start", name).CombinedOutput(); err != nil {
		t.Fatalf("docker start: %v\n%s", err, out)
	}
	for i := 0; i < 60; i++ {
		if exec.Command("docker", "exec", name, "test", "-f", "/tmp/ldap-ready").Run() == nil {
			return port
		}
		time.Sleep(time.Second)
	}
	logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
	t.Fatalf("%s did not become ready:\n%s", name, logs)
	return 0
}

// A generic LDAP server (OpenLDAP) is cloned with the ldap profile: groupOfNames needs a member at creation,
// the fixed password goes into userPassword, the relax control keeps the source's entryUUID and creation metadata,
// and renames are found through entryUUID with neither a marker nor a mapping file.
func TestGenericLDAPCloneWithOpenLDAP(t *testing.T) {
	image := os.Getenv("E2E_LDAP_IMAGE")
	if image == "" {
		t.Skip("E2E_LDAP_IMAGE is not set (tests/e2e.sh builds it)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker")
	}
	host := env("E2E_LAB_HOST", "localhost")
	suffix := time.Now().UnixNano() % 1_000_000
	srcName, dstName := fmt.Sprintf("olsrc%d", suffix), fmt.Sprintf("oldst%d", suffix)
	srcPort, dstPort := startOpenLDAP(t, image, srcName, nil), startOpenLDAP(t, image, dstName, map[string]string{"50-acl.ldif": olACL})
	accounts := exec.Command("docker", "exec", "-i", dstName, "ldapadd", "-x", "-H", "ldap://localhost", "-D", olAdmin, "-w", olPw)
	accounts.Stdin = strings.NewReader("dn: cn=cloner," + olBase + "\nobjectClass: person\ncn: cloner\nsn: c\nuserPassword: cloner-pw\n\n" +
		"dn: cn=writer," + olBase + "\nobjectClass: person\ncn: writer\nsn: w\nuserPassword: writer-pw\n")
	if out, err := accounts.CombinedOutput(); err != nil {
		t.Fatalf("accounts: %v\n%s", err, out)
	}

	seed := exec.Command("docker", "exec", "-i", srcName, "ldapadd", "-x", "-H", "ldap://localhost", "-D", olAdmin, "-w", olPw)
	seed.Stdin = strings.NewReader(olSeed)
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed: %v\n%s", err, out)
	}
	dialAs := func(port int, bindDN, pw string) *ldapdir.Client {
		c, err := ldapdir.Dial(ldapdir.ConnConfig{URL: fmt.Sprintf("ldap://%s:%d", host, port), BindDN: bindDN, Password: pw}, 4)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		return c
	}
	// The target is written by an account that has manage, not by the rootdn, as on a shared production server.
	src, dst := dialAs(srcPort, olAdmin, olPw), dialAs(dstPort, "cn=cloner,"+olBase, "cloner-pw")

	prof, err := profile.Detect(context.Background(), src)
	if err != nil || prof.Name != profile.NameLDAP {
		t.Fatalf("OpenLDAP must be detected as a generic server: %v %v", prof.Name, err)
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
[source]
url = "ldap://%s:%d"
bind_dn = %q
[target]
url = "ldap://%s:%d"
bind_dn = %q
[scope]
base_dn = %q
`, host, srcPort, olAdmin, host, dstPort, olAdmin, olClone)))
	if err != nil {
		t.Fatal(err)
	}
	opt, err := cfg.JobFor(prof)
	if err != nil {
		t.Fatal(err)
	}

	// With only write, the relax control is refused and clone stops with the remedy before creating anything.
	writer := dialAs(dstPort, "cn=writer,"+olBase, "writer-pw")
	_, err = clone.Run(context.Background(), src, writer, opt, clone.Options{UserPassword: "Fixed-Passw0rd", Workers: 1, Preserve: true, Operational: true}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "manage") {
		t.Fatalf("a bind without manage must stop clone with the remedy: %v", err)
	}
	if e, err := dst.Get(context.Background(), olClone, []string{"objectClass"}); err != nil || e != nil {
		t.Fatalf("nothing may be created: %v %v", e, err)
	}

	var out bytes.Buffer
	rep, err := clone.Run(context.Background(), src, dst, opt, clone.Options{UserPassword: "Fixed-Passw0rd", Workers: 4, Preserve: true, Operational: true}, &out)
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out.String())
	}
	// 7 with the group under alice: a parent leaf, which a generic server allows. alice is cloned as the user she
	// is (OpenLDAP refuses an inetOrgPerson without sn), and logs in with the fixed password below.
	if rep.Added != 7 {
		t.Fatalf("expected 7 objects: %+v\n%s", *rep, out.String())
	}
	// The application entry is of no kind: not cloned, and counted by its structuralObjectClass.
	if fmt.Sprint(rep.NotCloned) != "map[applicationProcess:1]" {
		t.Fatalf("not cloned: %v", rep.NotCloned)
	}

	diffs, err := runDiffWith(opt, src, dst, nil)
	if err != nil || len(diffs) != 0 {
		t.Fatalf("diff after clone: %v %+v", err, diffs)
	}

	// A dump of the source stands for it: entryUUID and the creation metadata, which "*" does not return, are read by
	// name and kept so; diff against the dump finds nothing, and a clone from it writes nothing more.
	var dumped bytes.Buffer
	if _, err := dump.Write(context.Background(), src, prof, dump.Options{BaseDNs: []string{olClone}, Server: "ldap://openldap"}, &dumped); err != nil {
		t.Fatal(err)
	}
	dumpPath := filepath.Join(t.TempDir(), "openldap.ldif")
	if err := os.WriteFile(dumpPath, dumped.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	fromDump, err := ldifdir.Open(dumpPath)
	if err != nil {
		t.Fatal(err)
	}
	if res, why, err := diff.ChooseResolver(context.Background(), fromDump, dst, opt, nil); err != nil || res == nil {
		t.Fatalf("the preserved entryUUID, read from the dump: %q %v", why, err)
	} else if diffs, err := runDiffWith(opt, fromDump, dst, res); err != nil || len(diffs) != 0 {
		t.Fatalf("diff against the dump: %v %+v", err, diffs)
	}
	again, err := clone.Run(context.Background(), fromDump, dst, opt, clone.Options{UserPassword: "Fixed-Passw0rd", Workers: 4, Preserve: true, Operational: true}, &bytes.Buffer{})
	if err != nil || again.Added != 0 || again.Updated != 0 {
		t.Fatalf("a clone from the dump finds everything in place: %+v %v", again, err)
	}

	login := func(user, pw string) error {
		conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, dstPort))
		if err != nil {
			return err
		}
		defer conn.Close()
		return conn.Bind(user, pw)
	}
	alice := "uid=alice,ou=People," + olClone
	if err := login(alice, "Fixed-Passw0rd"); err != nil {
		t.Fatalf("the fixed password must work: %v", err)
	}
	if err := login(alice, "secret-alice"); err == nil {
		t.Fatal("the source's password must not have been copied")
	}

	// The relax control kept the identifier and the creation metadata, written by an account with manage.
	// Only the OU is checked for the modification metadata: the memberof overlay rewrites the members' memberOf
	// when the group is added, which updates their modifyTimestamp as it does on production.
	keep := []string{"entryUUID", "createTimestamp", "modifyTimestamp", "creatorsName", "modifiersName"}
	for _, d := range []string{olClone, alice, "cn=Eng,ou=Groups," + olClone} {
		if d != olClone {
			keep = []string{"entryUUID", "createTimestamp", "creatorsName"}
		}
		want, err := src.Get(context.Background(), d, keep)
		if err != nil {
			t.Fatal(err)
		}
		got, err := dst.Get(context.Background(), d, keep)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range keep {
			if w, g := want.Values(a), got.Values(a); len(w) != 1 || len(g) != 1 || w[0] != g[0] {
				t.Fatalf("%s %s: source %v, target %v", d, a, w, g)
			}
		}
	}
	// A second run changes nothing: the creation-only attributes are never sent again.
	if rep, err := clone.Run(context.Background(), src, dst, opt, clone.Options{UserPassword: "Fixed-Passw0rd", Workers: 4, Preserve: true, Operational: true}, &bytes.Buffer{}); err != nil || rep.Updated != 0 {
		t.Fatalf("re-run: %+v %v", rep, err)
	}

	// Rename and move on the target, then find the entry again by the preserved entryUUID.
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, dstPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Bind(olAdmin, olPw); err != nil {
		t.Fatal(err)
	}
	if err := conn.ModifyDN(ldap.NewModifyDNRequest("uid=bob,ou=People,"+olClone, "uid=robert", true, "ou=Groups,"+olClone)); err != nil {
		t.Fatal(err)
	}
	res, why, err := diff.ChooseResolver(context.Background(), src, dst, opt, nil)
	if err != nil || res == nil {
		t.Fatalf("the preserved entryUUID must be recognized: %q %v", why, err)
	}
	diffs, err = runDiffWith(opt, src, dst, res)
	if err != nil {
		t.Fatal(err)
	}
	renamed := false
	for _, d := range diffs {
		if d.Kind == diff.Renamed && strings.EqualFold(d.DN, "uid=bob,ou=People,"+olClone) {
			renamed = true
		}
	}
	if !renamed {
		t.Fatalf("the rename must be found through the preserved entryUUID: %+v", diffs)
	}

	// A parent leaf renamed on the target takes its child along: alice is RENAMED, and the group under her is
	// neither missing nor extra.
	if err := conn.ModifyDN(ldap.NewModifyDNRequest(alice, "uid=alice2", true, "")); err != nil {
		t.Fatal(err)
	}
	diffs, err = runDiffWith(opt, src, dst, res)
	if err != nil {
		t.Fatal(err)
	}
	renamed = false
	for _, d := range diffs {
		switch {
		case d.Kind == diff.Renamed && strings.EqualFold(d.DN, alice):
			renamed = true
		case (d.Kind == diff.OnlySource || d.Kind == diff.OnlyTarget) && strings.Contains(strings.ToLower(d.DN), "cn=devices"):
			t.Errorf("the child of a renamed parent leaf must not be missing or extra: %+v", d)
		}
	}
	if !renamed {
		t.Fatalf("the rename of the parent leaf must be found: %+v", diffs)
	}
}

// Through the commands' session, the default on a generic server copies every attribute a client can write on the
// classes the entries hold: an inetOrgPerson's carLicense, which no allow list names, and what the auxiliary
// posixAccount and shadowAccount allow; with [mapping] mode = "preserve" (the default) beside it, the source's
// entryUUID and creation metadata, sent once in the Add, and memberOf left to the target's overlay. diff then finds
// nothing, and a second clone writes nothing.
func TestEveryAttributeOfOpenLDAPIsCopiedWithItsEntryUUID(t *testing.T) {
	image := os.Getenv("E2E_LDAP_IMAGE")
	if image == "" {
		t.Skip("E2E_LDAP_IMAGE is not set (tests/e2e.sh builds it)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker")
	}
	ctx := context.Background()
	host := env("E2E_LAB_HOST", "localhost")
	suffix := time.Now().UnixNano() % 1_000_000
	srcName, dstName := fmt.Sprintf("olasrc%d", suffix), fmt.Sprintf("oladst%d", suffix)
	srcPort, dstPort := startOpenLDAP(t, image, srcName, nil), startOpenLDAP(t, image, dstName, nil)
	seed := exec.Command("docker", "exec", "-i", srcName, "ldapadd", "-x", "-H", "ldap://localhost", "-D", olAdmin, "-w", olPw)
	seed.Stdin = strings.NewReader(`dn: ou=IDM,dc=example,dc=org
objectClass: organizationalUnit
ou: IDM

dn: uid=carol,ou=IDM,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: Carol
sn: C
uid: carol
carLicense: CAR-1
uidNumber: 1001
gidNumber: 1001
homeDirectory: /home/carol
loginShell: /bin/zsh
shadowLastChange: 20000

dn: cn=Ops,ou=IDM,dc=example,dc=org
objectClass: groupOfNames
cn: Ops
member: uid=carol,ou=IDM,dc=example,dc=org
`)
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed: %v\n%s", err, out)
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nurl = \"ldap://%s:%d\"\nbind_dn = %q\n[target]\nurl = \"ldap://%s:%d\"\nbind_dn = %q\n[scope]\nbase_dn = %q\n",
		host, srcPort, olAdmin, host, dstPort, olAdmin, olClone)))
	if err != nil {
		t.Fatal(err)
	}
	pw := func() (string, error) { return olPw, nil }
	s, err := app.Open(ctx, cfg, app.Secrets{SourceBind: pw, TargetBind: pw, UserPassword: func() (string, error) { return "Fixed-Passw0rd", nil }}, app.LDAP, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if !s.Job.AllWritable {
		t.Fatal("every attribute a client can write is the default on a generic server")
	}
	var log bytes.Buffer
	if _, err := s.Clone(ctx, false, &log, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	carol := "uid=carol," + olClone
	src, dst := dialAt(t, host, srcPort), dialAt(t, host, dstPort)
	attrs := []string{"carLicense", "uidNumber", "loginShell", "shadowLastChange", "entryUUID", "createTimestamp", "creatorsName", "memberOf"}
	want, err := src.Get(ctx, carol, attrs)
	if err != nil || want == nil {
		t.Fatal(want, err)
	}
	got, err := dst.Get(ctx, carol, attrs)
	if err != nil || got == nil {
		t.Fatalf("carol: %v %v\n%s", got, err, log.String())
	}
	for _, a := range attrs {
		if w, g := strings.Join(want.Values(a), "|"), strings.Join(got.Values(a), "|"); w == "" || w != g {
			t.Errorf("%s: source %q, target %q", a, w, g)
		}
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &out); err != nil || code != app.ExitSame {
		t.Fatalf("diff: %d %v\n%s", code, err, out.String())
	}
	log.Reset()
	if rep, err := s.Clone(ctx, false, &log, &log); err != nil || rep.Added != 0 || rep.Updated != 0 {
		t.Fatalf("a second clone: %+v %v\n%s", rep, err, log.String())
	}
}

func dialAt(t *testing.T, host string, port int) *ldapdir.Client {
	t.Helper()
	c, err := ldapdir.Dial(ldapdir.ConnConfig{URL: fmt.Sprintf("ldap://%s:%d", host, port), BindDN: olAdmin, Password: olPw}, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// A source's schema extension reaches an OpenLDAP target from a dump, as an AD's does: check names what the target
// lacks, schema -apply adds it to the target's cn=config as the lab's admin, and clone then copies the extension's
// attribute, which diff finds in place; schema again has nothing to add.
func TestASchemaExtensionReachesOpenLDAPFromADump(t *testing.T) {
	image := os.Getenv("E2E_LDAP_IMAGE")
	if image == "" {
		t.Skip("E2E_LDAP_IMAGE is not set (tests/e2e.sh builds it)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker")
	}
	ctx := context.Background()
	host := env("E2E_LAB_HOST", "localhost")
	suffix := time.Now().UnixNano() % 1_000_000
	srcName, dstName := fmt.Sprintf("olssrc%d", suffix), fmt.Sprintf("olsdst%d", suffix)
	srcPort := startOpenLDAP(t, image, srcName, map[string]string{"10-acme.ldif": acmeSchema})
	dstPort := startOpenLDAP(t, image, dstName, nil)
	seed := exec.Command("docker", "exec", "-i", srcName, "ldapadd", "-x", "-H", "ldap://localhost", "-D", olAdmin, "-w", olPw)
	seed.Stdin = strings.NewReader(`dn: ou=IDM,dc=example,dc=org
objectClass: organizationalUnit
ou: IDM

dn: uid=dave,ou=IDM,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: acmePerson
cn: Dave
sn: D
uid: dave
acmeEmployeeCode: E-42
`)
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed: %v\n%s", err, out)
	}
	src := dialAt(t, host, srcPort)
	var dumped bytes.Buffer
	if _, err := dump.Write(ctx, src, profile.LDAP, dump.Options{BaseDNs: []string{olClone}, Server: "ldap://openldap"}, &dumped); err != nil {
		t.Fatal(err)
	}
	dumpPath := filepath.Join(t.TempDir(), "acme.ldif")
	if err := os.WriteFile(dumpPath, dumped.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nldif = %q\n[target]\nurl = \"ldap://%s:%d\"\nbind_dn = %q\n[scope]\nprofile = \"ldap\"\nbase_dn = %q\n",
		dumpPath, host, dstPort, olAdmin, olClone)))
	if err != nil {
		t.Fatal(err)
	}
	pw := func() (string, error) { return olPw, nil }
	s, err := app.Open(ctx, cfg, app.Secrets{TargetBind: pw, UserPassword: func() (string, error) { return "Fixed-Passw0rd", nil }}, app.LDAP, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	var report bytes.Buffer
	if _, err := s.Check(ctx, app.CheckOptions{Config: "c.toml"}, &report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report.String(), "acmeEmployeeCode") || !strings.Contains(report.String(), "ldap-cronin schema -config c.toml -apply") {
		t.Fatalf("check must name the extension and the step:\n%s", report.String())
	}
	var out, log bytes.Buffer
	if err := s.Schema(ctx, true, &out, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if !strings.Contains(log.String(), "acmeEmployeeCode") || !strings.Contains(log.String(), "acmePerson") || !strings.Contains(log.String(), ",cn=schema,cn=config") {
		t.Fatalf("schema -apply:\n%s", log.String())
	}
	log.Reset()
	if _, err := s.Clone(ctx, false, &log, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	got, err := dialAt(t, host, dstPort).Get(ctx, "uid=dave,"+olClone, []string{"acmeEmployeeCode", "objectClass"})
	if err != nil || got == nil || strings.Join(got.Values("acmeEmployeeCode"), "") != "E-42" {
		t.Fatalf("dave: %+v %v\n%s", got, err, log.String())
	}
	var diffOut bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &diffOut); err != nil || code != app.ExitSame {
		t.Fatalf("diff: %d %v\n%s", code, err, diffOut.String())
	}
	log.Reset()
	if err := s.Schema(ctx, false, &out, &log); err != nil || !strings.Contains(log.String(), "has every attribute and class") {
		t.Fatalf("schema again: %v\n%s", err, log.String())
	}
}

// A base_dn that is an o= database suffix, which no DC= run names, is its own root against real OpenLDAP: dump
// writes the whole directory under it, clone from the server copies it, and diff against the server and the dump
// finds nothing.
func TestAnOSuffixIsItsOwnRoot(t *testing.T) {
	image := os.Getenv("E2E_LDAP_IMAGE")
	if image == "" {
		t.Skip("E2E_LDAP_IMAGE is not set (tests/e2e.sh builds it)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker")
	}
	const suffix = "o=acme"
	admin := "cn=admin," + suffix
	ctx := context.Background()
	host := env("E2E_LAB_HOST", "localhost")
	run := time.Now().UnixNano() % 1_000_000
	srcName, dstName := fmt.Sprintf("olosrc%d", run), fmt.Sprintf("olodst%d", run)
	srcPort, dstPort := startOpenLDAPAt(t, image, srcName, suffix, nil), startOpenLDAPAt(t, image, dstName, suffix, nil)
	seed := exec.Command("docker", "exec", "-i", srcName, "ldapadd", "-x", "-H", "ldap://localhost", "-D", admin, "-w", olPw)
	seed.Stdin = strings.NewReader(`dn: ou=People,o=acme
objectClass: organizationalUnit
ou: People

dn: uid=erin,ou=People,o=acme
objectClass: inetOrgPerson
cn: Erin
sn: E
uid: erin
mail: erin@example.org

dn: cn=Ops,o=acme
objectClass: groupOfNames
cn: Ops
member: uid=erin,ou=People,o=acme
`)
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed: %v\n%s", err, out)
	}
	pw := func() (string, error) { return olPw, nil }
	secrets := app.Secrets{SourceBind: pw, TargetBind: pw, UserPassword: func() (string, error) { return "Fixed-Passw0rd", nil }}
	target := fmt.Sprintf("[target]\nurl = \"ldap://%s:%d\"\nbind_dn = %q\n[scope]\nbase_dn = %q\n", host, dstPort, admin, suffix)
	open := func(source string) *app.Session {
		t.Helper()
		cfg, err := config.Parse([]byte(source + target))
		if err != nil {
			t.Fatal(err)
		}
		s, err := app.Open(ctx, cfg, secrets, app.LDAP, &bytes.Buffer{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}

	dumpPath := filepath.Join(t.TempDir(), "acme.ldif.gz")
	c, err := app.Dump(ctx, app.DumpOptions{Conn: ldapdir.ConnConfig{URL: fmt.Sprintf("ldap://%s:%d", host, srcPort), BindDN: admin},
		BaseDNs: []string{suffix}, Out: dumpPath, Version: "e2e"}, pw, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("dump -base-dn %s: %v", suffix, err)
	}
	if c.Base < 4 { // the suffix, the OU, the user and the group
		t.Fatalf("the dump holds %+v", c)
	}

	s := open(fmt.Sprintf("[source]\nurl = \"ldap://%s:%d\"\nbind_dn = %q\n", host, srcPort, admin))
	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if rep.Added != 3 {
		t.Fatalf("the OU, the user and the group: %+v\n%s", rep, log.String())
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &out); err != nil || code != app.ExitSame {
		t.Fatalf("diff against the server: %d %v\n%s", code, err, out.String())
	}
	out.Reset()
	if code, err := open(fmt.Sprintf("[source]\nldif = %q\n", dumpPath)).Diff(ctx, app.DiffOutput{}, &out); err != nil || code != app.ExitSame {
		t.Fatalf("diff against the dump: %d %v\n%s", code, err, out.String())
	}
}

// olChangedInetOrgPerson changes the standard inetOrgPerson as a production may have: an attribute type of its own,
// defined in the same cn=config entry, named in the class's MAY rather than in an auxiliary class.
const olChangedInetOrgPerson = `dn: cn={3}inetorgperson,cn=schema,cn=config
changetype: modify
add: olcAttributeTypes
olcAttributeTypes: ( 1.3.6.1.4.1.99999.1.30 NAME 'acmeLockFlag' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
-
replace: olcObjectClasses
olcObjectClasses: ( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' DESC 'RFC2798: Internet Organizational Person' SUP organizationalPerson STRUCTURAL MAY ( audio $ businessCategory $ carLicense $ departmentNumber $ displayName $ employeeNumber $ employeeType $ givenName $ homePhone $ homePostalAddress $ initials $ jpegPhoto $ labeledURI $ mail $ manager $ mobile $ o $ pager $ photo $ roomNumber $ secretary $ uid $ userCertificate $ x500uniqueIdentifier $ preferredLanguage $ userSMIMECertificate $ userPKCS12 $ acmeLockFlag ) )
-
`

// A standard class the source changed reaches OpenLDAP: before the schema, clone leaves the attribute out with a note
// and completes, whether the target lacks its type or has it (an earlier copy added it in an entry of its own) but
// not in its inetOrgPerson; schema -apply changes the target's inetOrgPerson to the source's, moved after the entry
// that defines the type; clone then copies the attribute, diff finds nothing, and the target still starts after a
// restart, which a class naming an attribute loaded after it would stop.
func TestAChangedStandardClassReachesOpenLDAP(t *testing.T) {
	image := os.Getenv("E2E_LDAP_IMAGE")
	if image == "" {
		t.Skip("E2E_LDAP_IMAGE is not set (tests/e2e.sh builds it)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker")
	}
	ctx := context.Background()
	host := env("E2E_LAB_HOST", "localhost")
	run := time.Now().UnixNano() % 1_000_000
	srcName, dstName := fmt.Sprintf("olcsrc%d", run), fmt.Sprintf("olcdst%d", run)
	srcPort := startOpenLDAP(t, image, srcName, map[string]string{"10-inetorgperson.ldif": olChangedInetOrgPerson})
	dstPort := startOpenLDAP(t, image, dstName, nil)
	seed := exec.Command("docker", "exec", "-i", srcName, "ldapadd", "-x", "-H", "ldap://localhost", "-D", olAdmin, "-w", olPw)
	seed.Stdin = strings.NewReader(`dn: ou=IDM,dc=example,dc=org
objectClass: organizationalUnit
ou: IDM

dn: uid=frank,ou=IDM,dc=example,dc=org
objectClass: inetOrgPerson
cn: Frank
sn: F
uid: frank
acmeLockFlag: 1
`)
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed: %v\n%s", err, out)
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nurl = \"ldap://%s:%d\"\nbind_dn = %q\n[target]\nurl = \"ldap://%s:%d\"\nbind_dn = %q\n[scope]\nbase_dn = %q\n",
		host, srcPort, olAdmin, host, dstPort, olAdmin, olClone)))
	if err != nil {
		t.Fatal(err)
	}
	pw := func() (string, error) { return olPw, nil }
	s, err := app.Open(ctx, cfg, app.Secrets{SourceBind: pw, TargetBind: pw, UserPassword: func() (string, error) { return "Fixed-Passw0rd", nil }}, app.LDAP, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	frank := "uid=frank," + olClone
	flag := func() string {
		t.Helper()
		e, err := dialAt(t, host, dstPort).Get(ctx, frank, []string{"acmeLockFlag"})
		if err != nil || e == nil {
			t.Fatalf("frank: %v %v", e, err)
		}
		return strings.Join(e.Values("acmeLockFlag"), "")
	}

	// The target defines no acmeLockFlag yet: left out as an attribute the target lacks, the rest cloned.
	var log bytes.Buffer
	if _, err := s.Clone(ctx, false, &log, &log); err != nil {
		t.Fatalf("clone before the schema: %v\n%s", err, log.String())
	}
	if flag() != "" || !strings.Contains(log.String(), "acmeLockFlag") {
		t.Fatalf("before the schema:\n%s", log.String())
	}
	// The type alone, as an earlier copy carried it: the target's inetOrgPerson still refuses it.
	types := exec.Command("docker", "exec", "-i", dstName, "ldapmodify", "-x", "-H", "ldap://localhost", "-D", olAdmin, "-w", olPw)
	types.Stdin = strings.NewReader("dn: cn=ldap-cronin-earlier,cn=schema,cn=config\nchangetype: add\nobjectClass: olcSchemaConfig\ncn: ldap-cronin-earlier\n" +
		"olcAttributeTypes: ( 1.3.6.1.4.1.99999.1.30 NAME 'acmeLockFlag' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )\n")
	if out, err := types.CombinedOutput(); err != nil {
		t.Fatalf("the earlier copy: %v\n%s", err, out)
	}
	log.Reset()
	if _, err := s.Clone(ctx, false, &log, &log); err != nil {
		t.Fatalf("clone with the type but not the class: %v\n%s", err, log.String())
	}
	if flag() != "" || !strings.Contains(log.String(), "do not allow 1 attributes the source's do") || !strings.Contains(log.String(), "acmeLockFlag (user: ") {
		t.Fatalf("with the type but not the class:\n%s", log.String())
	}
	log.Reset()
	var out bytes.Buffer
	if err := s.Schema(ctx, true, &out, &log); err != nil {
		t.Fatalf("schema -apply: %v\n%s", err, log.String())
	}
	if !strings.Contains(log.String(), "classes to change to the source's: 1\n  inetOrgPerson") || !strings.Contains(log.String(), "modify cn={3}inetorgperson,cn=schema,cn=config") ||
		!strings.Contains(log.String(), "modify cn={4}ldap-cronin-earlier,cn=schema,cn=config") {
		t.Fatalf("schema -apply:\n%s", log.String())
	}
	log.Reset()
	if _, err := s.Clone(ctx, false, &log, &log); err != nil {
		t.Fatalf("clone after the schema: %v\n%s", err, log.String())
	}
	if flag() != "1" {
		t.Fatalf("acmeLockFlag after the schema:\n%s", log.String())
	}
	var diffOut bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &diffOut); err != nil || code != app.ExitSame {
		t.Fatalf("diff: %d %v\n%s", code, err, diffOut.String())
	}
	log.Reset()
	if err := s.Schema(ctx, false, &out, &log); err != nil || !strings.Contains(log.String(), "has every attribute and class") {
		t.Fatalf("schema again: %v\n%s", err, log.String())
	}

	// slapd loads cn=config again at a start: the changed class must find its attribute before it.
	if out, err := exec.Command("docker", "restart", dstName).CombinedOutput(); err != nil {
		t.Fatalf("restart: %v\n%s", err, out)
	}
	for i := 0; ; i++ {
		if exec.Command("docker", "exec", dstName, "test", "-f", "/tmp/ldap-ready").Run() == nil {
			break
		}
		if i == 60 {
			logs, _ := exec.Command("docker", "logs", "--tail", "20", dstName).CombinedOutput()
			t.Fatalf("the target did not start again:\n%s", logs)
		}
		time.Sleep(time.Second)
	}
	if flag() != "1" {
		t.Fatal("acmeLockFlag after the restart")
	}
}

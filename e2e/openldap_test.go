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

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
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
	port := freePort(t)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	out, err := exec.Command("docker", "create", "--name", name, "-p", fmt.Sprintf("%d:389", port),
		"-e", "LDAP_SUFFIX="+olBase, "-e", "LDAP_ADMIN_PASSWORD="+olPw, image).CombinedOutput()
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

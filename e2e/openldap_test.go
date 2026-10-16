//go:build e2e

package e2e

import (
	"bytes"
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
	"github.com/wadahiro/ldap-cronin/internal/guidmap"
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
`

// startOpenLDAP runs a throw-away OpenLDAP and returns its host port.
func startOpenLDAP(t *testing.T, image, name string) int {
	t.Helper()
	port := freePort(t)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	out, err := exec.Command("docker", "run", "-d", "--name", name, "-p", fmt.Sprintf("%d:389", port),
		"-e", "LDAP_ADMIN_PASSWORD="+olPw, "-e", "LDAP_TLS=false", image).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	for i := 0; i < 60; i++ {
		probe := exec.Command("docker", "exec", name, "ldapsearch", "-x", "-H", "ldap://localhost", "-D", olAdmin, "-w", olPw, "-b", olBase, "-s", "base", "dn")
		if probe.Run() == nil {
			return port
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("%s did not become ready", name)
	return 0
}

// A generic LDAP server (OpenLDAP) is cloned with the ldap profile: groupOfNames needs a member at creation,
// the fixed password goes into userPassword, and renames are found through entryUUID.
func TestGenericLDAPCloneWithOpenLDAP(t *testing.T) {
	image := os.Getenv("E2E_OPENLDAP_IMAGE")
	if image == "" {
		t.Skip("E2E_OPENLDAP_IMAGE is not set")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker")
	}
	host := env("E2E_LAB_HOST", "localhost")
	suffix := time.Now().UnixNano() % 1_000_000
	srcName, dstName := fmt.Sprintf("olsrc%d", suffix), fmt.Sprintf("oldst%d", suffix)
	srcPort, dstPort := startOpenLDAP(t, image, srcName), startOpenLDAP(t, image, dstName)

	seed := exec.Command("docker", "exec", "-i", srcName, "ldapadd", "-x", "-H", "ldap://localhost", "-D", olAdmin, "-w", olPw)
	seed.Stdin = strings.NewReader(olSeed)
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed: %v\n%s", err, out)
	}
	dial := func(port int) *ldapdir.Client {
		c, err := ldapdir.Dial(ldapdir.ConnConfig{URL: fmt.Sprintf("ldap://%s:%d", host, port), BindDN: olAdmin, Password: olPw}, 4)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		return c
	}
	src, dst := dial(srcPort), dial(dstPort)

	prof, err := profile.Detect(src)
	if err != nil || prof.Name != profile.NameLDAP {
		t.Fatalf("OpenLDAP must be detected as a generic server: %v %v", prof.Name, err)
	}
	src.SetRangedAttrs(prof.RangedAttrs)
	dst.SetRangedAttrs(prof.RangedAttrs)
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
[source]
url = "ldap://%s:%d"
bind_dn = %q
[target]
url = "ldap://%s:%d"
bind_dn = %q
[clone]
base_dn = %q
`, host, srcPort, olAdmin, host, dstPort, olAdmin, olClone)))
	if err != nil {
		t.Fatal(err)
	}
	opt, err := cfg.PlanOptionsFor(prof)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	rep, err := clone.Run(src, dst, clone.Options{Plan: opt, UserPassword: "Fixed-Passw0rd", Workers: 4}, &out)
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out.String())
	}
	if rep.Added != 6 {
		t.Fatalf("expected 6 objects: %+v\n%s", *rep, out.String())
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

	// Rename and move on the target, then find the entry again by entryUUID through a mapping.
	mapPath := t.TempDir() + "/map.tsv"
	srcID, err := guidmap.RootID(src, olBase, opt.IDAttr())
	if err != nil {
		t.Fatal(err)
	}
	dstID, err := guidmap.RootID(dst, olBase, opt.IDAttr())
	if err != nil {
		t.Fatal(err)
	}
	if srcID == dstID {
		t.Fatal("two servers must have different root identifiers")
	}
	gm, err := guidmap.Open(mapPath, guidmap.Header{SourceDomain: srcID, TargetDomain: dstID, BaseDN: olClone})
	if err != nil {
		t.Fatal(err)
	}
	trackOpt := opt
	trackOpt.TrackGUID = true
	if _, err := clone.Run(src, dst, clone.Options{Plan: trackOpt, UserPassword: "Fixed-Passw0rd", Workers: 4, GUIDMap: gm}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := gm.Close(); err != nil {
		t.Fatal(err)
	}
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
	loaded, err := guidmap.Load(mapPath, guidmap.Header{SourceDomain: srcID, TargetDomain: dstID, BaseDN: olClone})
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	diffs, err = runDiffWith(opt, src, dst, loaded)
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
		t.Fatalf("the rename must be found through entryUUID: %+v", diffs)
	}
}

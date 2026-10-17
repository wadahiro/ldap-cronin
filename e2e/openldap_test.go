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
// the fixed password goes into userPassword, the relax control keeps the source's entryUUID and creation metadata,
// and renames are found through entryUUID with neither a marker nor a mapping file.
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

	var out bytes.Buffer
	rep, err := clone.Run(context.Background(), src, dst, opt, clone.Options{UserPassword: "Fixed-Passw0rd", Workers: 4, Preserve: true, Operational: true}, &out)
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

	// The relax control kept the identifier and the creation metadata (the source bind is the rootdn, as is the target's).
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
}

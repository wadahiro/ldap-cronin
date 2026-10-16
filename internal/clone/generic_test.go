package clone

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/attrs"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/mask"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

const (
	gRoot  = "dc=example,dc=org"
	gBase  = "ou=IDM," + gRoot
	gAlice = "uid=alice,ou=People," + gBase
	gBob   = "uid=bob,ou=People," + gBase
	gEng   = "cn=Eng,ou=Groups," + gBase
)

func genericOptions(t *testing.T) plan.Options {
	t.Helper()
	resolved := map[string][]string{}
	for _, k := range attrs.Kinds {
		list, err := attrs.ResolveFor(profile.LDAP, k, attrs.Override{})
		if err != nil {
			t.Fatal(err)
		}
		resolved[k] = list
	}
	return plan.Options{Profile: profile.LDAP, BaseDN: gBase, Kinds: allKinds(), Attrs: resolved, Masker: mask.New("***", nil)}
}

func genericSource() *fakedir.Dir {
	d := fakedir.New(gRoot)
	d.Put(gBase, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}})
	d.Put("ou=People,"+gBase, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"People"}})
	d.Put("ou=Groups,"+gBase, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Groups"}})
	d.Put(gAlice, map[string][]string{"objectClass": {"top", "inetOrgPerson"}, "cn": {"Alice"}, "sn": {"A"}, "uid": {"alice"},
		"mail": {"alice@example.org"}, "userPassword": {"{SSHA}real-hash"}})
	d.Put(gBob, map[string][]string{"objectClass": {"top", "inetOrgPerson"}, "cn": {"Bob"}, "sn": {"B"}, "uid": {"bob"}, "manager": {gAlice}})
	d.Put(gEng, map[string][]string{"objectClass": {"top", "groupOfNames"}, "cn": {"Eng"},
		"member": {gAlice, gBob, "uid=outsider,ou=Elsewhere," + gRoot}})
	return d
}

func TestGenericCloneSetsUserPasswordInsteadOfUnicodePwd(t *testing.T) {
	src, dst := genericSource(), fakedir.New(gRoot)
	if _, err := Run(src, dst, Options{Plan: genericOptions(t), UserPassword: "Fixed1!", Workers: 1}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	got := dst.Lookup(gAlice)
	if got == nil {
		t.Fatal("alice was not cloned")
	}
	if pw := got.Values("userPassword"); len(pw) != 1 || pw[0] != "Fixed1!" {
		t.Fatalf("the fixed password must replace the source's hash: %v", pw)
	}
	if len(got.Values("unicodePwd")) != 0 || len(got.Values("userAccountControl")) != 0 {
		t.Fatalf("AD password attributes must not appear on a generic server: %v", got.Attrs)
	}
}

func TestGenericCloneCreatesGroupsThatRequireAMemberAtCreation(t *testing.T) {
	src, dst := genericSource(), fakedir.New(gRoot)
	dst.RequireAttr = map[string]string{"groupofnames": "member"}
	rep, err := Run(src, dst, Options{Plan: genericOptions(t), UserPassword: "Fixed1!", Workers: 1}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	members := dst.Lookup(gEng).Values("member")
	if len(members) != 2 {
		t.Fatalf("both in-scope members must be present and the outsider skipped: %v", members)
	}
	if rep.WarningCount != 1 || !strings.Contains(rep.Warnings[0], "outsider") {
		t.Fatalf("the out-of-scope member must be reported: %+v", rep)
	}
}

func TestGenericCloneCreatesUsersBeforeGroups(t *testing.T) {
	src, dst := genericSource(), fakedir.New(gRoot)
	if _, err := Run(src, dst, Options{Plan: genericOptions(t), UserPassword: "x", Workers: 1}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var user, group int
	for i, op := range dst.Ops {
		if op == "add "+gBob {
			user = i
		}
		if op == "add "+gEng {
			group = i
		}
	}
	if user > group {
		t.Fatalf("a server that checks member references needs the users first: %v", dst.Ops)
	}
}

func TestGenericDiffFindsNoDifferenceAfterClone(t *testing.T) {
	src, dst := genericSource(), fakedir.New(gRoot)
	opt := genericOptions(t)
	if _, err := Run(src, dst, Options{Plan: opt, UserPassword: "x", Workers: 1}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var got []string
	diffs := runDiff(t, src, dst, opt)
	for _, d := range diffs {
		got = append(got, string(d.Kind)+" "+d.DN)
	}
	if len(diffs) != 0 {
		t.Fatalf("unexpected differences: %v", got)
	}
}

var _ directory.Directory = (*fakedir.Dir)(nil)

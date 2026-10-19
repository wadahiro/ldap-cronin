package clone

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// gDevices is a group under a user: a generic server has no structure rules, and production has such entries.
const gDevices = "cn=Devices," + gAlice

func genericParentLeafSource() *fakedir.Dir {
	src := genericSource()
	src.Put(gDevices, map[string][]string{"objectClass": {"top", "groupOfNames"}, "cn": {"Devices"}, "member": {gBob}})
	return src
}

// strictGeneric is a target that enforces what the classes need: sn of inetOrgPerson, a member of groupOfNames.
func strictGeneric() *fakedir.Dir {
	dst := fakedir.New(gRoot)
	dst.RequireAttr = map[string]string{"inetorgperson": "sn", "groupofnames": "member"}
	return dst
}

func diffSummary(t *testing.T, src, dst *fakedir.Dir, job plan.Job) ([]string, diff.Summary) {
	t.Helper()
	var diffs []string
	sum, err := diff.Run(context.Background(), src, dst, job, diff.Options{Workers: 2}, func(d diff.Difference) {
		diffs = append(diffs, string(d.Kind)+" "+d.DN+" "+d.Attr)
	})
	if err != nil {
		t.Fatal(err)
	}
	return diffs, sum
}

// A leaf holding a child is the parent of an entry to clone. Created as an ancestor, with only the ancestor
// attributes, alice would miss sn (the server refuses her) and her password; she is cloned as the user she is,
// once, and diff compares her once.
func TestALeafWithChildrenIsClonedAsItsKind(t *testing.T) {
	src, dst, job := genericParentLeafSource(), strictGeneric(), genericOptions(t)
	opt := Options{UserPassword: "Fixed1!", Workers: 2}
	if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	a := dst.Lookup(gAlice)
	if a == nil || a.Values("sn") == nil || a.Values("mail") == nil || strings.Join(a.Values("userPassword"), "") != "Fixed1!" {
		t.Fatalf("alice must be cloned as a user: %+v", a)
	}
	if m := dst.Lookup(gDevices).Values("member"); len(m) != 1 {
		t.Fatalf("the child group must be cloned with its member: %v", m)
	}
	if n := countOps(dst, "add "+gAlice); n != 1 {
		t.Fatalf("alice must be added once, not %d times", n)
	}

	diffs, sum := diffSummary(t, src, dst, job)
	if len(diffs) != 0 {
		t.Fatalf("unexpected differences: %v", diffs)
	}
	if sum.Compared[profile.KindUser] != 2 || sum.Compared[profile.KindGroup] != 2 {
		t.Fatalf("every entry is compared once: %v", sum.Compared)
	}

	before := len(dst.Ops)
	if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if extra := dst.Ops[before:]; len(extra) != 0 {
		t.Fatalf("a rerun must write nothing: %v", extra)
	}

	dst.Lookup(gAlice).Attrs["sn"] = []string{"changed"}
	if diffs, _ := diffSummary(t, src, dst, job); len(diffs) != 1 || diffs[0] != "DIFF "+gAlice+" sn" {
		t.Fatalf("a change to the parent leaf must show once: %v", diffs)
	}
	delete(dst.Entries, strings.ToLower(gAlice))
	diffs, _ = diffSummary(t, src, dst, job)
	if len(diffs) != 1 || diffs[0] != "ONLY_SOURCE "+gAlice+" " {
		t.Fatalf("a missing parent leaf must show once: %v", diffs)
	}
}

// A parent leaf outside the scope (here above base_dn; a narrowed filter is the other way) is still needed as the
// parent: it is cloned as its kind, without its own references (as a referenced object is), and compared that way.
func TestAParentLeafOutsideTheScopeIsClonedWithoutItsReferences(t *testing.T) {
	const (
		svc  = "uid=svc,ou=IDM," + gRoot
		apps = "ou=Apps," + svc
		carl = "uid=carl," + apps
		team = "cn=Team," + apps
	)
	src := fakedir.New(gRoot)
	src.Put("ou=IDM,"+gRoot, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}})
	src.Put(svc, map[string][]string{"objectClass": {"top", "inetOrgPerson"}, "cn": {"svc"}, "sn": {"S"}, "uid": {"svc"}, "seeAlso": {team}})
	src.Put(apps, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Apps"}})
	src.Put(carl, map[string][]string{"objectClass": {"top", "inetOrgPerson"}, "cn": {"Carl"}, "sn": {"C"}, "uid": {"carl"}})
	src.Put(team, map[string][]string{"objectClass": {"top", "groupOfNames"}, "cn": {"Team"}, "member": {carl}})
	dst := strictGeneric()
	job := jobFor(t, profile.LDAP, apps, profile.LDAP.KindNames(), profile.Override{})

	rep, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 2}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	s := dst.Lookup(svc)
	if s == nil || s.Values("sn") == nil || s.Values("userPassword") == nil {
		t.Fatalf("svc must be cloned as a user: %+v", s)
	}
	if s.Values("seeAlso") != nil {
		t.Fatalf("its own references are not followed: %v", s.Values("seeAlso"))
	}
	if rep.Referenced != 1 {
		t.Fatalf("svc is counted as an object outside the scope: %+v", rep)
	}
	diffs, sum := diffSummary(t, src, dst, job)
	if len(diffs) != 0 {
		t.Fatalf("unexpected differences: %v", diffs)
	}
	if sum.Compared[profile.KindUser] != 1 || sum.Referenced != 1 {
		t.Fatalf("carl is compared in the scope, svc outside it: %+v", sum)
	}
	dst.Lookup(svc).Attrs["sn"] = []string{"changed"}
	if diffs, _ := diffSummary(t, src, dst, job); len(diffs) != 1 || diffs[0] != "DIFF "+svc+" sn" {
		t.Fatalf("a change to it shows: %v", diffs)
	}
}

// AD: a group under a user. The user goes through the account steps (password, userAccountControl).
func TestAnADUserWithAChildGetsTheAccountSteps(t *testing.T) {
	src := seedSource()
	devices := "CN=Devices," + alice
	src.Put(devices, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Devices"}, "sAMAccountName": {"Devices"}, "member": {bob}})
	dst, job := fakedir.New(domain), options(t, allKinds()...)
	rep, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 2}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Updated != 0 {
		t.Fatalf("alice is created as a user, not created as a parent and updated afterwards: %+v", rep)
	}
	a := dst.Lookup(alice)
	if a.Values("unicodePwd") == nil || strings.Join(a.Values("userAccountControl"), "") != "512" || a.Values("sAMAccountName") == nil {
		t.Fatalf("alice must be cloned as an account: %+v", a.Attrs)
	}
	var diffs []string
	sum, err := diff.Run(context.Background(), src, dst, job, diff.Options{Workers: 2}, func(d diff.Difference) {
		diffs = append(diffs, string(d.Kind)+" "+d.DN+" "+d.Attr)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(diffs) != 0 || sum.Compared[profile.KindUser] != 2 {
		t.Fatalf("diffs %v compared %v", diffs, sum.Compared)
	}
}

// A rename of a parent leaf on the target moves its children with it: only the parent is RENAMED, the child is
// explained by it.
func TestARenamedParentLeafExplainsItsChildren(t *testing.T) {
	src := seedSource()
	devices := "CN=Devices," + alice
	src.Put(devices, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Devices"}, "sAMAccountName": {"Devices"}, "member": {bob}})
	_, dst, guids := clonedFrom(t, src)

	renamed := "CN=Alice Smith,OU=Tokyo,OU=Users," + base
	moveEntry(dst, alice, renamed)
	moveEntry(dst, devices, "CN=Devices,"+renamed)
	followRename(dst, alice, renamed)

	diffs, sum := diffWith(t, src, dst, guids)
	if len(diffs) != 1 || diffs[0].Kind != diff.Renamed || diffs[0].DN != alice || diffs[0].TargetDN != renamed {
		t.Fatalf("want only alice as RENAMED, got %s: %+v", kindsOf(diffs), diffs)
	}
	if sum.Implied != 1 {
		t.Fatalf("the child moved along with its parent: implied=%d", sum.Implied)
	}
}

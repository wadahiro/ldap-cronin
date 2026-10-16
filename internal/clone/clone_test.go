package clone

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/attrs"
	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/mask"
	"github.com/wadahiro/ldap-cronin/internal/plan"
)

const (
	domain = "DC=ad,DC=example,DC=com"
	base   = "OU=IDM," + domain
	tokyo  = "OU=Tokyo,OU=Users," + base
	staff  = "CN=Staff,OU=Users," + base
	alice  = "CN=Alice,OU=Tokyo,OU=Users," + base
	bob    = `CN=Doe\, Bob,CN=Staff,OU=Users,` + base
	eng    = "CN=Eng,OU=Groups," + base
)

func seedSource() *fakedir.Dir {
	d := fakedir.New(domain)
	d.Put("OU=IDM,"+domain, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}})
	d.Put("OU=Users,"+base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Users"}})
	d.Put("OU=Groups,"+base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Groups"}})
	d.Put(tokyo, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Tokyo"}})
	d.Put(staff, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Staff"}})
	d.Put(alice, map[string][]string{
		"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {"Alice"},
		"sAMAccountName": {"alice"}, "mail": {"alice@real.example"}, "userAccountControl": {"512"},
		"manager": {bob}, "extensionAttribute1": {"x"},
	})
	d.Put(bob, map[string][]string{
		"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {"Doe, Bob"},
		"sAMAccountName": {"bob"}, "userAccountControl": {"514"},
	})
	d.Put(eng, map[string][]string{
		"objectClass": {"top", "group"}, "cn": {"Eng"}, "sAMAccountName": {"Eng"},
		"member": {alice, bob, "CN=Domain Admins,CN=Users," + domain},
	})
	return d
}

func options(t *testing.T, kinds ...string) plan.Options {
	t.Helper()
	resolved := map[string][]string{}
	for _, k := range attrs.Kinds {
		list, err := attrs.Resolve(k, attrs.Override{})
		if err != nil {
			t.Fatal(err)
		}
		resolved[k] = list
	}
	return plan.Options{BaseDN: base, Kinds: kinds, Attrs: resolved, Masker: mask.New("***", []string{"mail"})}
}

// runDiff collects every result of diff.Run (for small tests).
func runDiff(t *testing.T, src, dst directory.Directory, opt plan.Options) []diff.Difference {
	t.Helper()
	var diffs []diff.Difference
	if _, err := diff.Run(src, dst, opt, 4, nil, func(d diff.Difference) { diffs = append(diffs, d) }); err != nil {
		t.Fatal(err)
	}
	return diffs
}

func allKinds() []string { return append([]string(nil), attrs.Kinds...) }

func TestCloneCreatesParentsFirstAndAppliesEverything(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	// fakedir.Add fails unless parents are created first. The order must hold across depth boundaries even in parallel.
	rep, err := Run(src, dst, Options{Plan: options(t, allKinds()...), UserPassword: "Fixed1!", Workers: 8}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Added != 8 {
		t.Fatalf("added=%d", rep.Added)
	}
	a := dst.Lookup(alice)
	if got := a.Values("mail"); len(got) != 1 || got[0] != "***" {
		t.Fatalf("mail not masked: %v", got)
	}
	if a.Values("extensionAttribute1") != nil {
		t.Fatal("extensionAttribute1 must not be copied by default")
	}
	if a.Values("userAccountControl")[0] != "512" || dst.Lookup(bob).Values("userAccountControl")[0] != "514" {
		t.Fatal("UAC not preserved")
	}
	if pw := a.Values("unicodePwd"); len(pw) != 1 || pw[0] != EncodePassword("Fixed1!") {
		t.Fatal("password not set")
	}
	if a.Values("manager")[0] != bob {
		t.Fatalf("manager: %v", a.Values("manager"))
	}
	members := dst.Lookup(eng).Values("member")
	if len(members) != 2 {
		t.Fatalf("members (builtin must be skipped as it is absent on target): %v", members)
	}
}

func TestCloneIsIdempotent(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	opt := Options{Plan: options(t, allKinds()...), UserPassword: "Fixed1!", Workers: 4}
	if _, err := Run(src, dst, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	before := len(dst.Ops)
	rep, err := Run(src, dst, opt, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Added != 0 || rep.Updated != 0 {
		t.Fatalf("second run changed things: %+v", rep)
	}
	if extra := dst.Ops[before:]; len(extra) != 0 {
		t.Fatalf("re-run must not write anything (passwords and UAC included): %v", extra)
	}
}

func TestCloneWithoutOUKindStillCreatesAncestors(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	if _, err := Run(src, dst, Options{Plan: options(t, attrs.KindUser), Workers: 2}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{base, "OU=Users," + base, tokyo, staff, alice, bob} {
		if dst.Lookup(d) == nil {
			t.Errorf("missing %s", d)
		}
	}
	if dst.Lookup(eng) != nil {
		t.Error("group must not be cloned")
	}
}

func TestCloneUpdatesChangedAttributeOnly(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	opt := Options{Plan: options(t, allKinds()...), Workers: 1}
	if _, err := Run(src, dst, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	src.Lookup(alice).Attrs["sAMAccountName"] = []string{"alice2"}
	rep, err := Run(src, dst, opt, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Updated != 1 || dst.Lookup(alice).Values("sAMAccountName")[0] != "alice2" {
		t.Fatalf("%+v", rep)
	}
}

func TestCloneRefusesDomainRootAsBase(t *testing.T) {
	o := options(t, allKinds()...)
	o.BaseDN = domain
	if _, err := Run(seedSource(), fakedir.New(domain), Options{Plan: o}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestDiffReportsMissingExtraAndChangedButIgnoresMask(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	opt := options(t, allKinds()...)
	if _, err := Run(src, dst, Options{Plan: opt, Workers: 4}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if diffs := runDiff(t, src, dst, opt); len(diffs) != 0 {
		t.Fatalf("clean clone must have no diff (masked mail differs by design): %v", diffs)
	}

	dst.Lookup(alice).Attrs["sAMAccountName"] = []string{"tampered"}
	dst.Delete(bob)
	dst.Put("OU=Stray,"+base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Stray"}})
	diffs := runDiff(t, src, dst, opt)
	var kinds []string
	for _, d := range diffs {
		kinds = append(kinds, string(d.Kind))
	}
	got := strings.Join(kinds, ",")
	for _, want := range []string{"DIFF", "ONLY_SOURCE", "ONLY_TARGET"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
}

func TestEncodePasswordIsQuotedUTF16LE(t *testing.T) {
	if got := EncodePassword("ab"); got != "\"\x00a\x00b\x00\"\x00" {
		t.Fatalf("%q", got)
	}
}

func TestDryRunNeverPrintsPassword(t *testing.T) {
	var out bytes.Buffer
	dst := dryRun(&out)
	if _, err := Run(seedSource(), dst, Options{Plan: options(t, allKinds()...), UserPassword: "TopSecret!"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "TopSecret") || strings.Contains(out.String(), EncodePassword("TopSecret!")) {
		t.Fatal("password leaked")
	}
	if !strings.Contains(out.String(), "changetype: add") {
		t.Fatal(out.String())
	}
}

func TestAncestorsAreMaskedToo(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	src.Lookup("OU=IDM," + domain).Attrs["description"] = []string{"secret org"}
	src.Lookup(tokyo).Attrs["description"] = []string{"secret tokyo"}
	opt := options(t, attrs.KindUser) // ou is not targeted: created via ancestors
	opt.Masker = mask.New("***", []string{"description"})
	if _, err := Run(src, dst, Options{Plan: opt, Workers: 2}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"OU=IDM," + domain, tokyo} {
		if got := dst.Lookup(d).Values("description"); len(got) != 1 || got[0] != "***" {
			t.Errorf("%s description=%v", d, got)
		}
	}
}

func TestDiffOnEmptyTargetListsEverythingAsMissing(t *testing.T) {
	diffs := runDiff(t, seedSource(), fakedir.New(domain), options(t, allKinds()...))
	if len(diffs) == 0 {
		t.Fatal("expected MISSING entries")
	}
	for _, d := range diffs {
		if d.Kind != diff.OnlySource {
			t.Fatalf("unexpected %+v", d)
		}
	}
}

func TestMissingBaseDNOnSourceIsAnError(t *testing.T) {
	o := options(t, allKinds()...)
	o.BaseDN = "OU=Typo," + domain
	if _, err := Run(seedSource(), fakedir.New(domain), Options{Plan: o}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected error instead of an empty plan")
	}
}

func TestInterruptedUserGetsPasswordOnRerun(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	opt := Options{Plan: options(t, allKinds()...), UserPassword: "Fixed1!", Workers: 1}
	if _, err := Run(src, dst, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	delete(dst.Lookup(alice).Attrs, "unicodePwd")
	dst.Lookup(alice).Attrs["pwdLastSet"] = []string{"0"}
	if _, err := Run(src, dst, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if dst.Lookup(alice).Values("unicodePwd") == nil {
		t.Fatal("password must be set when pwdLastSet=0")
	}
}

func TestDiffFlagsCaseOnlyDifferencesAndCountsThem(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	src.Lookup(alice).Attrs["title"] = []string{"Manager"}
	opt := options(t, allKinds()...)
	if _, err := Run(src, dst, Options{Plan: opt, Workers: 2}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	dst.Lookup(alice).Attrs["title"] = []string{"manager"}      // case only
	dst.Lookup(alice).Attrs["sAMAccountName"] = []string{"zed"} // genuinely different value

	var diffs []diff.Difference
	sum, err := diff.Run(src, dst, opt, 2, nil, func(d diff.Difference) { diffs = append(diffs, d) })
	if err != nil {
		t.Fatal(err)
	}
	byAttr := map[string]diff.Difference{}
	for _, d := range diffs {
		byAttr[d.Attr] = d
	}
	if !byAttr["title"].CaseOnly || byAttr["sAMAccountName"].CaseOnly {
		t.Fatalf("case-only flag wrong: %+v", byAttr)
	}
	if sum.Differences[diff.Differ] != 2 || sum.CaseOnly != 1 {
		t.Fatalf("a case-only difference still counts as a difference: %+v", sum)
	}
}

package clone

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/mask"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
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

// jobFor builds a job the way config does: kinds in the profile's order, resolved allow lists.
func jobFor(t *testing.T, p profile.Profile, baseDN string, kinds []string, o profile.Override, maskAttrs ...string) plan.Job {
	t.Helper()
	job := plan.Job{Profile: p, BaseDNs: []string{baseDN}, Masker: mask.New("***", maskAttrs)}
	for _, spec := range p.Kinds {
		enabled := false
		for _, k := range kinds {
			enabled = enabled || k == spec.Name
		}
		if !enabled {
			continue
		}
		list, err := p.Attrs(spec.Name, o)
		if err != nil {
			t.Fatal(err)
		}
		job.Kinds = append(job.Kinds, plan.NewKind(p, spec, "", list))
	}
	return job
}

// options is the AD job of most tests: mail is masked.
func options(t *testing.T, kinds ...string) plan.Job {
	t.Helper()
	return jobFor(t, profile.AD, base, kinds, profile.Override{}, "mail")
}

// runDiff collects every result of diff.Run (for small tests).
func runDiff(t *testing.T, src, dst directory.Directory, opt plan.Job) []diff.Difference {
	t.Helper()
	var diffs []diff.Difference
	if _, err := diff.Run(context.Background(), src, dst, opt, diff.Options{Workers: 4}, func(d diff.Difference) { diffs = append(diffs, d) }); err != nil {
		t.Fatal(err)
	}
	return diffs
}

func allKinds() []string { return profile.AD.KindNames() }

func TestCloneCreatesParentsFirstAndAppliesEverything(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	// fakedir.Add fails unless parents are created first. The order must hold across depth boundaries even in parallel.
	rep, err := Run(context.Background(), src, dst, options(t, allKinds()...), Options{UserPassword: "Fixed1!", Workers: 8}, &bytes.Buffer{})
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
	if pw := a.Values("unicodePwd"); len(pw) != 1 || pw[0] != profile.EncodePassword("Fixed1!") {
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
	job, opt := options(t, allKinds()...), Options{UserPassword: "Fixed1!", Workers: 4}
	if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	before := len(dst.Ops)
	rep, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{})
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

// The account strategy owns userAccountControl: a re-run restores a value changed on the target, through Finish
// alone, and leaves the source entry untouched for it (the generic comparison must not see or strip it).
func TestRerunRestoresUserAccountControlChangedOnTheTarget(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	job, opt := options(t, allKinds()...), Options{UserPassword: "Fixed1!", Workers: 2}
	if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	dst.Lookup(alice).Attrs["userAccountControl"] = []string{"514"} // disabled by the program under test
	before := len(dst.Ops)
	var log bytes.Buffer
	rep, err := Run(context.Background(), src, dst, job, opt, &log)
	if err != nil {
		t.Fatal(err)
	}
	if got := dst.Lookup(alice).Values("userAccountControl"); len(got) != 1 || got[0] != "512" || rep.Updated != 1 {
		t.Fatalf("UAC=%v report=%+v", got, rep)
	}
	if extra := dst.Ops[before:]; len(extra) != 1 || !strings.Contains(extra[0], "replace userAccountControl") {
		t.Fatalf("only Finish may write it, once, and no password reset: %v", extra)
	}
	if !strings.Contains(log.String(), "update "+alice+" (userAccountControl)") {
		t.Fatal(log.String())
	}
	if v := src.Lookup(alice).Values("userAccountControl"); len(v) != 1 || v[0] != "512" {
		t.Fatalf("the source entry must not be changed: %v", v)
	}
}

func TestCloneWithoutOUKindStillCreatesAncestors(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	if _, err := Run(context.Background(), src, dst, options(t, profile.KindUser), Options{Workers: 2}, &bytes.Buffer{}); err != nil {
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
	job, opt := options(t, allKinds()...), Options{Workers: 1}
	if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	src.Lookup(alice).Attrs["sAMAccountName"] = []string{"alice2"}
	rep, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Updated != 1 || dst.Lookup(alice).Values("sAMAccountName")[0] != "alice2" {
		t.Fatalf("%+v", rep)
	}
}

// Base DNs one of which is below another would clone their entries twice: refused before anything is written.
func TestCloneRefusesOverlappingBases(t *testing.T) {
	o := options(t, allKinds()...)
	o.BaseDNs = []string{base, "OU=Users," + base}
	dst := fakedir.New(domain)
	if _, err := Run(context.Background(), seedSource(), dst, o, Options{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "below") {
		t.Fatalf("overlapping bases: %v", err)
	}
	if len(dst.Ops) != 0 {
		t.Fatalf("written: %v", dst.Ops)
	}
}

// Several base DNs are one scope: a reference from one to another is a reference of the scope, written in full;
// what neither holds is a referenced object, as with one base DN. diff then finds nothing.
func TestSeveralBaseDNsAreOneScope(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	o := options(t, allKinds()...)
	o.BaseDNs = []string{tokyo, "OU=Groups," + base}
	rep, err := Run(context.Background(), src, dst, o, Options{UserPassword: "Fixed1!", Workers: 4}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ReferencedKinds["user"] != 1 {
		t.Fatalf("Bob, in neither base DN, is the one referenced object: %+v", rep.ReferencedKinds)
	}
	members := strings.Join(dst.Lookup(eng).Values("member"), "|")
	if !strings.Contains(members, alice) || !strings.Contains(members, bob) {
		t.Fatalf("Eng (in the second base DN) holds Alice (in the first): %s", members)
	}
	if got := strings.Join(dst.Lookup(alice).Values("manager"), ""); got != bob {
		t.Fatalf("Alice's manager: %q", got)
	}
	if diffs := runDiff(t, src, dst, o); len(diffs) != 0 {
		t.Fatalf("diff: %+v", diffs)
	}
}

func TestDiffReportsMissingExtraAndChangedButIgnoresMask(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	opt := options(t, allKinds()...)
	if _, err := Run(context.Background(), src, dst, opt, Options{Workers: 4}, &bytes.Buffer{}); err != nil {
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

func TestDryRunNeverPrintsPassword(t *testing.T) {
	var out bytes.Buffer
	dst := dryRun(&out)
	if _, err := Run(context.Background(), seedSource(), dst, options(t, allKinds()...), Options{UserPassword: "TopSecret!"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "TopSecret") || strings.Contains(out.String(), profile.EncodePassword("TopSecret!")) {
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
	opt := options(t, profile.KindUser) // ou is not targeted: created via ancestors
	opt.Masker = mask.New("***", []string{"description"})
	if _, err := Run(context.Background(), src, dst, opt, Options{Workers: 2}, &bytes.Buffer{}); err != nil {
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
	o.BaseDNs = []string{"OU=Typo," + domain}
	if _, err := Run(context.Background(), seedSource(), fakedir.New(domain), o, Options{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected error instead of an empty plan")
	}
}

func TestInterruptedUserGetsPasswordOnRerun(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	job, opt := options(t, allKinds()...), Options{UserPassword: "Fixed1!", Workers: 1}
	if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	// alice is created as a run stopped right after the add would leave her: no password, pwdLastSet=0 (set by the
	// fake as AD does).
	attrs := dst.Lookup(alice).Attrs
	dst.Delete(alice)
	delete(attrs, "unicodePwd")
	delete(attrs, "objectGUID")
	delete(attrs, "entryUUID")
	if err := dst.Add(context.Background(), directory.Entry{DN: alice, Attrs: attrs}); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
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
	if _, err := Run(context.Background(), src, dst, opt, Options{Workers: 2}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	dst.Lookup(alice).Attrs["title"] = []string{"manager"}      // case only
	dst.Lookup(alice).Attrs["sAMAccountName"] = []string{"zed"} // genuinely different value

	var diffs []diff.Difference
	sum, err := diff.Run(context.Background(), src, dst, opt, diff.Options{Workers: 2}, func(d diff.Difference) { diffs = append(diffs, d) })
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

// A user named "x,OU=Users" directly under OU=IDM and a user "x" in OU=Users have DNs that read alike once
// unescaped; they are two objects, and both are cloned and compared.
func TestDNsThatDifferOnlyByAnEscapedCommaAreTwoObjects(t *testing.T) {
	src, dst := fakedir.New(domain), fakedir.New(domain)
	src.Put(base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}})
	src.Put("OU=Users,"+base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Users"}})
	escaped, plain := `CN=x\,OU=Users,`+base, "CN=x,OU=Users,"+base
	userAt(src, escaped, "escaped")
	userAt(src, plain, "plain")
	src.Lookup(escaped).Attrs["cn"] = []string{"x,OU=Users"}
	job := options(t, allKinds()...)
	rep, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 2}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Added != 4 {
		t.Fatalf("two OUs and two users must be added: %+v", rep)
	}
	for _, d := range []string{escaped, plain} {
		if e := dst.Lookup(d); e == nil || !strings.EqualFold(e.DN, d) {
			t.Fatalf("%s is missing on the target", d)
		}
	}
	if diffs := runDiff(t, src, dst, job); len(diffs) != 0 {
		t.Fatalf("%+v", diffs)
	}
}

// A user who must change the password at the next logon on the source (pwdLastSet=0) must on the target too, and
// is not added to what clone writes as it is (AD refuses another pwdLastSet). A re-run sets the same password
// again; once the user has changed it, it is left alone.
func TestMustChangePasswordIsReproduced(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	src.Lookup(alice).Attrs["pwdLastSet"] = []string{"0"}
	job, opt := options(t, allKinds()...), Options{UserPassword: "Fixed1!", Workers: 1}
	if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	a := dst.Lookup(alice)
	if a.Values("unicodePwd") == nil || strings.Join(a.Values("pwdLastSet"), "") != "0" {
		t.Fatalf("alice must change her password: %v", a.Attrs)
	}
	for _, e := range dst.Entries {
		if e.DN != alice && len(e.Values("unicodePwd")) > 0 && strings.Join(e.Values("pwdLastSet"), "") == "0" {
			t.Fatalf("%s must not: %v", e.DN, e.Attrs)
		}
	}
	// She changed it: a re-run leaves it.
	a.Attrs["unicodePwd"] = []string{"hers"}
	a.Attrs["pwdLastSet"] = []string{"134000000000000000"}
	if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dst.Lookup(alice).Values("unicodePwd"), ""); got != "hers" {
		t.Fatalf("her own password was replaced: %q", got)
	}
}

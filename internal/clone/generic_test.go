package clone

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dryrun"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/identity"
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

func genericOptions(t *testing.T) plan.Job {
	t.Helper()
	return jobFor(t, profile.LDAP, gBase, profile.LDAP.KindNames(), profile.Override{})
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
	if _, err := Run(context.Background(), src, dst, genericOptions(t), Options{UserPassword: "Fixed1!", Workers: 1}, &bytes.Buffer{}); err != nil {
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
	rep, err := Run(context.Background(), src, dst, genericOptions(t), Options{UserPassword: "Fixed1!", Workers: 1}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	// A generic server takes any DN, so the member outside the scope is written too: every member is there.
	members := dst.Lookup(gEng).Values("member")
	if len(members) != 3 {
		t.Fatalf("every member of the source must be present: %v", members)
	}
	if rep.WarningCount != 0 {
		t.Fatalf("nothing is skipped: %+v", rep)
	}
}

func TestGenericCloneCreatesUsersBeforeGroups(t *testing.T) {
	src, dst := genericSource(), fakedir.New(gRoot)
	if _, err := Run(context.Background(), src, dst, genericOptions(t), Options{UserPassword: "x", Workers: 1}, &bytes.Buffer{}); err != nil {
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
	if _, err := Run(context.Background(), src, dst, opt, Options{UserPassword: "x", Workers: 1}, &bytes.Buffer{}); err != nil {
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

// A generic server identifies objects by entryUUID (text). The mapping file (mode = "file") records it, and a
// rename made on the target is found again through an entryUUID filter, without a real server.
func TestGenericRenameOnTargetIsFoundThroughEntryUUID(t *testing.T) {
	src, dst := genericSource(), fakedir.New(gRoot)
	header := identity.Header{Scheme: "entryUUID", SourceRoot: identity.Key{1}}
	path := filepath.Join(t.TempDir(), "mapping")
	m, err := identity.Open(path, header)
	if err != nil {
		t.Fatal(err)
	}
	opt := genericOptions(t)
	if _, err := Run(context.Background(), src, dst, opt, Options{UserPassword: "Fixed1!", Workers: 2, Mapping: m}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	guids, err := identity.Load(path, header)
	if err != nil {
		t.Fatal(err)
	}
	defer guids.Close()
	if guids.Len() == 0 {
		t.Fatal("the entryUUID pairs must be recorded")
	}

	renamed := "uid=alice2,ou=People," + gBase
	moveEntry(dst, gAlice, renamed)
	var diffs []diff.Difference
	if _, err := diff.Run(context.Background(), src, dst, genericOptions(t), diff.Options{Workers: 2, Resolver: identity.ByMap(guids, identity.EntryUUID)},
		func(d diff.Difference) { diffs = append(diffs, d) }); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range diffs {
		switch {
		case d.Kind == diff.Renamed && d.DN == gAlice && d.TargetDN == renamed:
			found = true
		case d.Kind == diff.OnlySource || d.Kind == diff.OnlyTarget:
			t.Errorf("a rename must not show up as a missing and an extra entry: %+v", d)
		}
	}
	if !found {
		t.Fatalf("the rename was not found through entryUUID: %+v", diffs)
	}
}

// cloneWithFile clones as clone does with [mapping] mode = "file": the pairs are in the file once it returns.
func cloneWithFile(t *testing.T, path string, src, dst *fakedir.Dir) {
	t.Helper()
	m, err := identity.Open(path, identity.Header{Scheme: "entryUUID", SourceRoot: identity.Key{1}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Run(context.Background(), src, dst, genericOptions(t), Options{UserPassword: "Fixed1!", Workers: 2, Mapping: m}, &bytes.Buffer{})
	if cerr := m.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
}

func diffWithFile(t *testing.T, path string, src, dst *fakedir.Dir) []string {
	t.Helper()
	m, err := identity.Load(path, identity.Header{Scheme: "entryUUID", SourceRoot: identity.Key{1}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var got []string
	if _, err := diff.Run(context.Background(), src, dst, genericOptions(t), diff.Options{Workers: 2, Resolver: identity.ByMap(m, identity.EntryUUID)},
		func(d diff.Difference) { got = append(got, string(d.Kind)+" "+d.DN) }); err != nil {
		t.Fatal(err)
	}
	return got
}

// The mapping file is a ledger: after clone ran again (alice was deleted and recreated with a new key), a restore
// brings back the earlier key, which is still alice's. A rename is still found, and an object recreated by hand is
// still REPLACED.
func TestMappingFileServesARestoreAfterAnotherClone(t *testing.T) {
	src, dst := genericSource(), fakedir.New(gRoot)
	dst.IDPrefix = 0xd1
	path := filepath.Join(t.TempDir(), "mapping")
	cloneWithFile(t, path, src, dst)
	snapshot := dst.Snapshot()
	dst.Delete(gAlice)
	cloneWithFile(t, path, src, dst)
	dst.Restore(snapshot)
	if got := diffWithFile(t, path, src, dst); len(got) != 0 {
		t.Fatalf("a restored clone must have no differences: %v", got)
	}

	renamed := "uid=alice2,ou=People," + gBase
	moveEntry(dst, gAlice, renamed)
	if got := diffWithFile(t, path, src, dst); !slices.Equal(got, []string{"RENAMED " + gAlice}) {
		t.Fatalf("the rename after the restore: %v", got)
	}
	moveEntry(dst, renamed, gAlice)
	attrs := dst.Lookup(gAlice).Attrs
	dst.Delete(gAlice)
	delete(attrs, "objectGUID")
	delete(attrs, "entryUUID")
	dst.Put(gAlice, attrs) // recreated by the program under test: a key never recorded
	if got := diffWithFile(t, path, src, dst); !slices.Equal(got, []string{"REPLACED " + gAlice}) {
		t.Fatalf("an object recreated on the target: %v", got)
	}
}

// One file serves two targets (two lab instances from one snapshot): each diffs clean after both were cloned into,
// and a rename on either is found.
func TestMappingFileServesTwoTargets(t *testing.T) {
	src := genericSource()
	main, dev2 := fakedir.New(gRoot), fakedir.New(gRoot)
	main.IDPrefix, dev2.IDPrefix = 0xd1, 0xd2
	path := filepath.Join(t.TempDir(), "mapping")
	cloneWithFile(t, path, src, main)
	cloneWithFile(t, path, src, dev2)
	carol := "uid=carol,ou=People," + gBase
	src.Put(carol, map[string][]string{"objectClass": {"top", "inetOrgPerson"}, "cn": {"Carol"}, "sn": {"C"}, "uid": {"carol"}})
	cloneWithFile(t, path, src, dev2)
	cloneWithFile(t, path, src, main)
	for name, dst := range map[string]*fakedir.Dir{"main": main, "dev2": dev2} {
		if got := diffWithFile(t, path, src, dst); len(got) != 0 {
			t.Fatalf("%s must have no differences: %v", name, got)
		}
	}
	moveEntry(dev2, carol, "uid=carol2,ou=People,"+gBase)
	if got := diffWithFile(t, path, src, dev2); !slices.Equal(got, []string{"RENAMED " + carol}) {
		t.Fatalf("a rename on dev2: %v", got)
	}
}

// The fixed password travels in the Add, so an account never exists without it, and a re-run never touches a
// password the program under test changed. The schema-violation retry for groupOfNames keeps it too.
func TestGenericPasswordIsSetAtCreationAndNeverReset(t *testing.T) {
	src, dst := genericSource(), fakedir.New(gRoot)
	dst.RequireAttr = map[string]string{"groupofnames": "member"}
	job, opt := genericOptions(t), Options{UserPassword: "Fixed1!", Workers: 2}
	if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, op := range dst.Ops {
		if strings.Contains(op, "userPassword") {
			t.Fatalf("the password must be part of the Add, not a separate modify: %v", dst.Ops)
		}
	}
	dst.Lookup(gAlice).Attrs["userPassword"] = []string{"Changed-by-the-program"}
	if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if pw := dst.Lookup(gAlice).Values("userPassword"); len(pw) != 1 || pw[0] != "Changed-by-the-program" {
		t.Fatalf("a re-run must not reset the password: %v", pw)
	}
}

func TestGenericDryRunNeverPrintsPassword(t *testing.T) {
	var out bytes.Buffer
	dst := dryrun.New(&out, profile.LDAP)
	if _, err := Run(context.Background(), genericSource(), dst, genericOptions(t), Options{UserPassword: "TopSecret!"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "TopSecret") || !strings.Contains(out.String(), "# userPassword: <redacted>") {
		t.Fatal(out.String())
	}
}

// With the relax control the target keeps the source's entryUUID and the creation metadata, so a rename is found
// by the identifier itself, with no marker and no file.
func TestGenericPreserveKeepsEntryUUIDAndTheOperationalAttributes(t *testing.T) {
	src, dst := genericSource(), fakedir.New(gRoot)
	src.Lookup(gAlice).Attrs["createTimestamp"] = []string{"20200102030405Z"}
	src.Lookup(gAlice).Attrs["creatorsName"] = []string{"cn=admin," + gRoot}
	dst.Relax = profile.RelaxOID
	var log bytes.Buffer
	if _, err := Run(context.Background(), src, dst, genericOptions(t), Options{UserPassword: "Fixed1!", Workers: 2, Preserve: true, Operational: true}, &log); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{gAlice, gEng, "ou=People," + gBase} {
		if want, got := src.Lookup(d).Values("entryUUID"), dst.Lookup(d).Values("entryUUID"); len(got) != 1 || got[0] != want[0] {
			t.Fatalf("%s: entryUUID %v, the source has %v", d, got, want)
		}
	}
	a := dst.Lookup(gAlice)
	if v := a.Values("createTimestamp"); len(v) != 1 || v[0] != "20200102030405Z" {
		t.Fatalf("createTimestamp %v", v)
	}
	if v := a.Values("creatorsName"); len(v) != 1 || v[0] != "cn=admin,"+gRoot {
		t.Fatalf("creatorsName %v (a DN-valued operational attribute is written at creation, not with the references)", v)
	}

	// A second run finds everything unchanged: the creation-only attributes are never sent again.
	rep, err := Run(context.Background(), src, dst, genericOptions(t), Options{UserPassword: "Fixed1!", Workers: 2, Preserve: true, Operational: true}, &log)
	if err != nil || rep.Updated != 0 {
		t.Fatalf("%+v %v", rep, err)
	}

	renamed := "uid=alice2,ou=People," + gBase
	moveEntry(dst, gAlice, renamed)
	var diffs []diff.Difference
	if _, err := diff.Run(context.Background(), src, dst, genericOptions(t), diff.Options{Workers: 2, Resolver: identity.ByIdentity(identity.EntryUUID)},
		func(d diff.Difference) { diffs = append(diffs, d) }); err != nil {
		t.Fatal(err)
	}
	if len(diffs) != 1 || diffs[0].Kind != diff.Renamed || diffs[0].TargetDN != renamed {
		t.Fatalf("%+v", diffs)
	}
}

// A target that refuses the control stops the clone with the remedy, instead of silently creating objects with new
// identifiers.
func TestGenericPreserveStopsWhenTheTargetRefusesTheControl(t *testing.T) {
	for name, dst := range map[string]*fakedir.Dir{
		"no manage access": {Entries: map[string]*directory.Entry{}, Relax: profile.RelaxOID, RelaxDenied: true},
		"unsupported":      {Entries: map[string]*directory.Entry{}},
	} {
		dst.Put(gRoot, map[string][]string{"objectClass": {"dcObject", "organization"}})
		_, err := Run(context.Background(), genericSource(), dst, genericOptions(t), Options{UserPassword: "Fixed1!", Workers: 1, Preserve: true}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "manage") || len(dst.Entries) != 1 {
			t.Fatalf("%s: %v (%d entries)", name, err, len(dst.Entries))
		}
	}
}

// On a server that needs a reference's entry, a groupOfNames whose members all name entries the target lacks
// cannot be created (the schema needs a member, and none can be written). Like such a reference, it is skipped with
// a warning, and the rest is cloned.
func TestAGroupWhoseMembersCannotBeWrittenIsSkippedWithAWarning(t *testing.T) {
	strict := profile.LDAP
	strict.RefsNeedEntry = true
	job := jobFor(t, strict, gBase, strict.KindNames(), profile.Override{})
	src, dst := genericSource(), fakedir.New(gRoot)
	dst.RequireAttr = map[string]string{"groupofnames": "member"}
	far := "cn=Far,ou=Groups," + gBase
	src.Put(far, map[string][]string{"objectClass": {"top", "groupOfNames"}, "cn": {"Far"}, "member": {"uid=outsider,ou=Elsewhere," + gRoot}})
	rep, err := Run(context.Background(), src, dst, job, Options{UserPassword: "x", Workers: 2}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("the rest must be cloned: %v", err)
	}
	if dst.Lookup(far) != nil || dst.Lookup(gEng) == nil {
		t.Fatal("Far must be skipped and Eng created")
	}
	found := false
	for _, w := range rep.Warnings {
		found = found || strings.Contains(w, "skip "+far)
	}
	if !found {
		t.Fatalf("the skip must be a warning: %v", rep.Warnings)
	}
	var kinds []string
	for _, d := range runDiff(t, src, dst, job) {
		kinds = append(kinds, string(d.Kind)+" "+d.DN)
	}
	if !slices.Equal(kinds, []string{"ONLY_SOURCE " + far}) {
		t.Fatalf("diff shows the skipped group as not cloned: %v", kinds)
	}
}

// A schema violation that is not about references (here a required attribute the source lacks) still stops the run.
func TestASchemaViolationOfAnEntryWithoutReferencesStopsTheRun(t *testing.T) {
	src, dst := genericSource(), fakedir.New(gRoot)
	dst.RequireAttr = map[string]string{"inetorgperson": "employeeNumber"}
	if _, err := Run(context.Background(), src, dst, genericOptions(t), Options{UserPassword: "x", Workers: 1}, &bytes.Buffer{}); !errors.Is(err, directory.ErrSchemaViolation) {
		t.Fatalf("got %v", err)
	}
}

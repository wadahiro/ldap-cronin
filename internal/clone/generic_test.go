package clone

import (
	"bytes"
	"context"
	"path/filepath"
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
	header := identity.Header{Scheme: "entryUUID", SourceRoot: identity.Key{1}, TargetRoot: identity.Key{2}, BaseDN: gBase}
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
	dst := dryrun.New(&out, profile.LDAP.PasswordAttrs)
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

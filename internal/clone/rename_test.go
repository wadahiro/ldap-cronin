package clone

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/guidmap"
)

var mapHeader = guidmap.Header{SourceDomain: "src-domain", TargetDomain: "dst-domain", BaseDN: base}

// clonedWithMapping clones the source to the target, records the GUID mapping and returns it reopened.
func clonedWithMapping(t *testing.T) (src, dst *fakedir.Dir, guids *guidmap.Map) {
	t.Helper()
	return clonedFrom(t, seedSource())
}

func clonedFrom(t *testing.T, src *fakedir.Dir) (_, dst *fakedir.Dir, guids *guidmap.Map) {
	t.Helper()
	dst = fakedir.New(domain)
	path := filepath.Join(t.TempDir(), "guid-map.tsv")
	m, err := guidmap.Open(path, mapHeader)
	if err != nil {
		t.Fatal(err)
	}
	opt := options(t, allKinds()...)
	opt.TrackGUID = true
	if _, err := Run(src, dst, Options{Plan: opt, Workers: 4, GUIDMap: m}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	guids, err = guidmap.Load(path, mapHeader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { guids.Close() })
	return src, dst, guids
}

// moveEntry reproduces another program changing a DN on the target. objectGUID does not change, and
// as on a real server the RDN attribute (cn / ou) also changes to match the new RDN.
func moveEntry(dst *fakedir.Dir, oldDN, newDN string) {
	e := dst.Lookup(oldDN)
	attrs := map[string][]string{}
	for k, v := range e.Attrs {
		attrs[k] = append([]string(nil), v...)
	}
	if typ, val, ok := dn.FirstRDN(newDN); ok {
		attrs[strings.ToLower(typ)] = []string{val}
	}
	dst.Delete(oldDN)
	dst.Put(newDN, attrs)
}

// userAt adds a user to be cloned to the source.
func userAt(src *fakedir.Dir, entryDN, sam string) {
	src.Put(entryDN, map[string][]string{
		"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {strings.TrimPrefix(dn.Split(entryDN)[0], "CN=")},
		"sAMAccountName": {sam},
	})
}

func diffWith(t *testing.T, src, dst *fakedir.Dir, guids *guidmap.Map) ([]diff.Difference, diff.Summary) {
	t.Helper()
	var diffs []diff.Difference
	sum, err := diff.Run(src, dst, options(t, allKinds()...), 4, guids, func(d diff.Difference) { diffs = append(diffs, d) })
	if err != nil {
		t.Fatal(err)
	}
	return diffs, sum
}

func kindsOf(diffs []diff.Difference) string {
	var k []string
	for _, d := range diffs {
		k = append(k, string(d.Kind))
	}
	return strings.Join(k, ",")
}

func TestCloneRecordsAGUIDPairForEveryObjectIncludingParents(t *testing.T) {
	_, _, guids := clonedWithMapping(t)
	if guids.Len() != 8 { // 4 OUs (IDM, Users, Groups, Tokyo) + container Staff + 2 users + 1 group
		t.Fatalf("pairs=%d", guids.Len())
	}
}

func TestRenamedObjectIsReportedAsRenamedNotAsAddedPlusRemoved(t *testing.T) {
	src, dst, guids := clonedWithMapping(t)
	renamed := "CN=Alice Smith,OU=Tokyo,OU=Users," + base
	moveEntry(dst, alice, renamed)

	diffs, sum := diffWith(t, src, dst, guids)
	if len(diffs) != 1 || diffs[0].Kind != diff.Renamed {
		t.Fatalf("want exactly one RENAMED, got %s", kindsOf(diffs))
	}
	d := diffs[0]
	if d.DN != alice || d.TargetDN != renamed || !d.RDNRenamed || d.Moved {
		t.Fatalf("%+v", d)
	}
	if sum.Differences[diff.Renamed] != 1 || sum.Differences[diff.OnlySource] != 0 || sum.Differences[diff.OnlyTarget] != 0 {
		t.Fatalf("%+v", sum.Differences)
	}
}

func TestMovedObjectEvenOutsideTheBaseDN(t *testing.T) {
	src, dst, guids := clonedWithMapping(t)
	moved := `CN=Doe\, Bob,CN=Users,` + domain // moved outside the starting point (same RDN)
	moveEntry(dst, bob, moved)

	diffs, _ := diffWith(t, src, dst, guids)
	if len(diffs) != 1 || diffs[0].Kind != diff.Renamed || diffs[0].TargetDN != moved || diffs[0].RDNRenamed || !diffs[0].Moved {
		t.Fatalf("got %s: %+v", kindsOf(diffs), diffs)
	}
}

// Requirement: even when a rename or move is detected, attribute differences are still reported, at the current DN on the target.
func TestAttributeDifferencesAreStillReportedForARenamedObject(t *testing.T) {
	src, dst, guids := clonedWithMapping(t)
	renamed := "CN=Alice Smith,OU=Tokyo,OU=Users," + base
	moveEntry(dst, alice, renamed)
	dst.Lookup(renamed).Attrs["title"] = []string{"Hacked"}
	src.Lookup(alice).Attrs["title"] = []string{"Manager"}

	diffs, _ := diffWith(t, src, dst, guids)
	var rename, attr *diff.Difference
	for i := range diffs {
		switch diffs[i].Kind {
		case diff.Renamed:
			rename = &diffs[i]
		case diff.Differ:
			attr = &diffs[i]
		}
	}
	if rename == nil || attr == nil || len(diffs) != 2 {
		t.Fatalf("want RENAMED and DIFF, got %s", kindsOf(diffs))
	}
	if attr.Attr != "title" || !dn.Equal(attr.DN, renamed) {
		t.Fatalf("the attribute difference must be shown at the object's current DN: %+v", attr)
	}
}

func TestMovingAnOUDoesNotReportEveryChildAsRenamed(t *testing.T) {
	src := seedSource()
	carol := "CN=Carol,OU=Tokyo,OU=Users," + base
	userAt(src, carol, "carol")
	_, dst, guids := clonedFrom(t, src)

	oldOU, newOU := "OU=Tokyo,OU=Users,"+base, "OU=Osaka,OU=Users,"+base
	moveEntry(dst, oldOU, newOU)
	moveEntry(dst, alice, "CN=Alice,"+newOU) // moved along with the OU (RDN unchanged)
	moveEntry(dst, carol, "CN=Carol,"+newOU)

	diffs, sum := diffWith(t, src, dst, guids)
	if len(diffs) != 1 || diffs[0].Kind != diff.Renamed || diffs[0].DN != oldOU || diffs[0].TargetDN != newOU {
		t.Fatalf("want only the OU as RENAMED, got %s: %+v", kindsOf(diffs), diffs)
	}
	if sum.Implied != 2 {
		t.Fatalf("the two children moved along with their parent: implied=%d", sum.Implied)
	}
}

func TestChildMovedAwayFromARenamedParentIsStillReported(t *testing.T) {
	src := seedSource()
	carol := "CN=Carol,OU=Tokyo,OU=Users," + base
	userAt(src, carol, "carol")
	_, dst, guids := clonedFrom(t, src)

	oldOU, newOU := "OU=Tokyo,OU=Users,"+base, "OU=Osaka,OU=Users,"+base
	moveEntry(dst, oldOU, newOU)
	moveEntry(dst, alice, "CN=Alice,"+newOU)          // moved along with the parent
	moveEntry(dst, carol, "CN=Carol,OU=Groups,"+base) // moved to a place unrelated to the parent

	diffs, sum := diffWith(t, src, dst, guids)
	if len(diffs) != 2 || sum.Differences[diff.Renamed] != 2 || sum.Implied != 1 {
		t.Fatalf("got %s implied=%d", kindsOf(diffs), sum.Implied)
	}
	for _, d := range diffs {
		if d.DN == carol && !d.Moved {
			t.Fatalf("carol was moved away from the parent: %+v", d)
		}
	}
}

func TestWithoutAMappingARenameLooksLikeOnlySourcePlusOnlyTarget(t *testing.T) {
	src, dst, _ := clonedWithMapping(t)
	moveEntry(dst, alice, "CN=Alice Smith,OU=Tokyo,OU=Users,"+base)

	diffs, _ := diffWith(t, src, dst, nil)
	if got := kindsOf(diffs); got != "ONLY_SOURCE,ONLY_TARGET" && got != "ONLY_TARGET,ONLY_SOURCE" {
		t.Fatalf("got %s", got)
	}
}

// If the target was rebuilt and GUIDs changed (stale mapping), entries are simply not found and nothing is falsely detected.
func TestStaleMappingFallsBackWithoutFalseRenames(t *testing.T) {
	src, dst, guids := clonedWithMapping(t)
	renamed := "CN=Alice Smith,OU=Tokyo,OU=Users," + base
	moveEntry(dst, alice, renamed)
	dst.Lookup(renamed).Attrs["objectGUID"] = []string{strings.Repeat("\xee", 16)} // a different GUID

	diffs, sum := diffWith(t, src, dst, guids)
	if sum.Differences[diff.Renamed] != 0 || len(diffs) != 2 {
		t.Fatalf("got %s", kindsOf(diffs))
	}
}

func TestSummaryStatesWhetherRenameDetectionWasOn(t *testing.T) {
	src, dst, guids := clonedWithMapping(t)
	var on, off bytes.Buffer
	_, sumOn := diffWith(t, src, dst, guids)
	_, sumOff := diffWith(t, src, dst, nil)
	diff.WriteSummary(&on, options(t, allKinds()...), sumOn, nil)
	diff.WriteSummary(&off, options(t, allKinds()...), sumOff, nil)
	if !strings.Contains(on.String(), "rename/move check: on (8 GUID pairs") || !strings.Contains(on.String(), "RENAMED") {
		t.Fatal(on.String())
	}
	if !strings.Contains(off.String(), "rename/move check: off") || strings.Contains(off.String(), "RENAMED     :") {
		t.Fatal(off.String())
	}
}

func TestFormatRenamed(t *testing.T) {
	var b bytes.Buffer
	diff.Format(&b, diff.Difference{Kind: diff.Renamed, DN: "CN=a,OU=X,DC=x", TargetDN: "CN=b,OU=Y,DC=x", RDNRenamed: true, Moved: true}, 10)
	want := "RENAMED     source: CN=a,OU=X,DC=x\n            target: CN=b,OU=Y,DC=x   (renamed and moved)\n"
	if b.String() != want {
		t.Fatalf("got\n%s", b.String())
	}
}

// Even for children "explained" by an OU move, attribute differences are reported at the current DN on the target.
func TestChildMovedWithItsParentStillShowsAttributeDifferences(t *testing.T) {
	src, dst, guids := clonedWithMapping(t)
	oldOU, newOU := "OU=Tokyo,OU=Users,"+base, "OU=Osaka,OU=Users,"+base
	moveEntry(dst, oldOU, newOU)
	moved := "CN=Alice," + newOU
	moveEntry(dst, alice, moved)
	dst.Lookup(moved).Attrs["title"] = []string{"Changed by another program"}

	diffs, sum := diffWith(t, src, dst, guids)
	var renamedKinds []string
	var attr *diff.Difference
	for i := range diffs {
		if diffs[i].Kind == diff.Differ {
			attr = &diffs[i]
		} else {
			renamedKinds = append(renamedKinds, diffs[i].DN)
		}
	}
	if len(renamedKinds) != 1 || renamedKinds[0] != oldOU {
		t.Fatalf("only the OU is RENAMED, got %v", renamedKinds)
	}
	if sum.Implied != 1 {
		t.Fatalf("alice moved with her parent: implied=%d", sum.Implied)
	}
	if attr == nil || attr.Attr != "title" || !dn.Equal(attr.DN, moved) {
		t.Fatalf("alice's attribute difference must be reported at her current DN: %+v", attr)
	}
}

// A child that moved with its parent OU and was also renamed (RDN) is reported as a rename (not as a move).
func TestChildRenamedInsideAMovedParentIsReportedAsRenamedOnly(t *testing.T) {
	src, dst, guids := clonedWithMapping(t)
	oldOU, newOU := "OU=Tokyo,OU=Users,"+base, "OU=Osaka,OU=Users,"+base
	moveEntry(dst, oldOU, newOU)
	moveEntry(dst, alice, "CN=Alice Smith,"+newOU)

	diffs, _ := diffWith(t, src, dst, guids)
	if len(diffs) != 2 {
		t.Fatalf("got %s", kindsOf(diffs))
	}
	for _, d := range diffs {
		if d.DN == alice && (!d.RDNRenamed || d.Moved) {
			t.Fatalf("alice was only renamed within her (moved) parent: %+v", d)
		}
	}
}

// If a user under a moved OU was deleted, it is reported as ONLY_SOURCE and is not lost in the move.
func TestChildDeletedAfterItsOUWasMovedIsStillReported(t *testing.T) {
	src := seedSource()
	carol := "CN=Carol,OU=Tokyo,OU=Users," + base
	userAt(src, carol, "carol")
	_, dst, guids := clonedFrom(t, src)

	oldOU, newOU := "OU=Tokyo,OU=Users,"+base, "OU=Osaka,OU=Users,"+base
	moveEntry(dst, oldOU, newOU)
	moveEntry(dst, alice, "CN=Alice,"+newOU)
	dst.Delete(carol) // Carol was deleted after the move (she exists nowhere on the target)

	diffs, sum := diffWith(t, src, dst, guids)
	got := map[string]string{}
	for _, d := range diffs {
		got[d.DN] = string(d.Kind)
	}
	if len(diffs) != 2 || got[oldOU] != "RENAMED" || got[carol] != "ONLY_SOURCE" {
		t.Fatalf("want RENAMED(OU) and ONLY_SOURCE(carol), got %v", got)
	}
	if sum.Implied != 1 { // only Alice, who was actually found on the target, is explained
		t.Fatalf("implied=%d", sum.Implied)
	}
}

// A user newly created on the target under a moved OU is reported as ONLY_TARGET.
func TestChildCreatedInsideAMovedOUIsReportedAsOnlyTarget(t *testing.T) {
	src, dst, guids := clonedWithMapping(t)
	oldOU, newOU := "OU=Tokyo,OU=Users,"+base, "OU=Osaka,OU=Users,"+base
	moveEntry(dst, oldOU, newOU)
	moveEntry(dst, alice, "CN=Alice,"+newOU)
	created := "CN=Newcomer," + newOU
	userAt(dst, created, "newcomer") // another program created it in the OU after the move

	diffs, _ := diffWith(t, src, dst, guids)
	got := map[string]string{}
	for _, d := range diffs {
		got[d.DN] = string(d.Kind)
	}
	if len(diffs) != 2 || got[oldOU] != "RENAMED" || got[created] != "ONLY_TARGET" {
		t.Fatalf("want RENAMED(OU) and ONLY_TARGET(newcomer), got %v", got)
	}
}

// Combinations of nested OUs three levels deep (child OU Shibuya under Tokyo, with a user below it).
const (
	tokyoOU   = "OU=Tokyo,OU=Users," + base
	shibuyaOU = "OU=Shibuya," + tokyoOU
	dave      = "CN=Dave," + shibuyaOU
)

func nestedSource() *fakedir.Dir {
	src := seedSource()
	src.Put(shibuyaOU, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Shibuya"}})
	userAt(src, dave, "dave")
	return src
}

type outcome struct {
	renamed map[string]diff.Difference // source DN → RENAMED
	others  []string                   // other than RENAMED
	implied int
}

func outcomeOf(t *testing.T, src, dst *fakedir.Dir, guids *guidmap.Map) outcome {
	t.Helper()
	diffs, sum := diffWith(t, src, dst, guids)
	o := outcome{renamed: map[string]diff.Difference{}, implied: sum.Implied}
	for _, d := range diffs {
		if d.Kind == diff.Renamed {
			o.renamed[d.DN] = d
		} else {
			o.others = append(o.others, string(d.Kind)+" "+d.DN)
		}
	}
	return o
}

func TestNestedOUsMovedTogetherReportOnlyTheTopOU(t *testing.T) {
	src, dst, guids := clonedFrom(t, nestedSource())
	newTop := "OU=Osaka,OU=Users," + base
	moveEntry(dst, tokyoOU, newTop)
	moveEntry(dst, shibuyaOU, "OU=Shibuya,"+newTop)
	moveEntry(dst, alice, "CN=Alice,"+newTop)
	moveEntry(dst, dave, "CN=Dave,OU=Shibuya,"+newTop)

	o := outcomeOf(t, src, dst, guids)
	if len(o.renamed) != 1 || o.renamed[tokyoOU].TargetDN != newTop || len(o.others) != 0 {
		t.Fatalf("only the top OU is RENAMED: %+v others=%v", o.renamed, o.others)
	}
	if o.implied != 3 { // child OU Shibuya, Alice, Dave
		t.Fatalf("implied=%d, want 3", o.implied)
	}
}

// Both the parent OU and the child OU were renamed separately.
func TestParentAndChildOUsRenamedSeparately(t *testing.T) {
	src, dst, guids := clonedFrom(t, nestedSource())
	newTop := "OU=Osaka,OU=Users," + base
	newChild := "OU=Namba," + newTop // the child OU is renamed too (inside the parent)
	moveEntry(dst, tokyoOU, newTop)
	moveEntry(dst, shibuyaOU, newChild)
	moveEntry(dst, alice, "CN=Alice,"+newTop)
	moveEntry(dst, dave, "CN=Dave,"+newChild)

	o := outcomeOf(t, src, dst, guids)
	top, child := o.renamed[tokyoOU], o.renamed[shibuyaOU]
	if len(o.renamed) != 2 || len(o.others) != 0 {
		t.Fatalf("want 2 RENAMED, got %+v others=%v", o.renamed, o.others)
	}
	if !top.RDNRenamed || top.Moved || top.TargetDN != newTop {
		t.Fatalf("top: %+v", top)
	}
	if !child.RDNRenamed || child.Moved || child.TargetDN != newChild { // moved with the parent and only its own name changed
		t.Fatalf("child OU was renamed inside its (moved) parent: %+v", child)
	}
	if o.implied != 2 { // Alice (follows the parent) and Dave (follows the renamed child OU)
		t.Fatalf("implied=%d, want 2", o.implied)
	}
}

// The parent OU moved, and only the child OU moved out of the parent separately.
func TestChildOUMovedOutOfAMovedParent(t *testing.T) {
	src, dst, guids := clonedFrom(t, nestedSource())
	newTop := "OU=Osaka,OU=Users," + base
	newChild := "OU=Shibuya,OU=Groups," + base
	moveEntry(dst, tokyoOU, newTop)
	moveEntry(dst, shibuyaOU, newChild)
	moveEntry(dst, alice, "CN=Alice,"+newTop)
	moveEntry(dst, dave, "CN=Dave,"+newChild)

	o := outcomeOf(t, src, dst, guids)
	top, child := o.renamed[tokyoOU], o.renamed[shibuyaOU]
	if len(o.renamed) != 2 || len(o.others) != 0 {
		t.Fatalf("want 2 RENAMED, got %+v others=%v", o.renamed, o.others)
	}
	if !top.RDNRenamed || top.Moved {
		t.Fatalf("top: %+v", top)
	}
	if child.RDNRenamed || !child.Moved || child.TargetDN != newChild { // moved to a place unrelated to the parent
		t.Fatalf("child OU left its parent: %+v", child)
	}
	if o.implied != 2 { // Alice (follows the parent) and Dave (follows the child OU)
		t.Fatalf("implied=%d, want 2", o.implied)
	}
}

// The parent OU did not move; only the child OU moved elsewhere.
func TestOnlyTheChildOUMovedWhileTheParentStays(t *testing.T) {
	src, dst, guids := clonedFrom(t, nestedSource())
	newChild := "OU=Shibuya,OU=Groups," + base
	moveEntry(dst, shibuyaOU, newChild)
	moveEntry(dst, dave, "CN=Dave,"+newChild)

	o := outcomeOf(t, src, dst, guids)
	child := o.renamed[shibuyaOU]
	if len(o.renamed) != 1 || len(o.others) != 0 || !child.Moved || child.RDNRenamed {
		t.Fatalf("got %+v others=%v", o.renamed, o.others)
	}
	if o.implied != 1 { // Dave merely followed the child OU
		t.Fatalf("implied=%d, want 1", o.implied)
	}
}

// If a user in the child OU jumped over the parent OU to another place, it is reported.
func TestUserMovedOutOfANestedMovedOU(t *testing.T) {
	src, dst, guids := clonedFrom(t, nestedSource())
	newTop := "OU=Osaka,OU=Users," + base
	moveEntry(dst, tokyoOU, newTop)
	moveEntry(dst, shibuyaOU, "OU=Shibuya,"+newTop)
	moveEntry(dst, alice, "CN=Alice,"+newTop)
	moveEntry(dst, dave, "CN=Dave,OU=Groups,"+base) // only Dave, to a completely different place

	o := outcomeOf(t, src, dst, guids)
	d := o.renamed[dave]
	if len(o.renamed) != 2 || len(o.others) != 0 || !d.Moved || d.RDNRenamed { // Tokyo and Dave
		t.Fatalf("got %+v others=%v", o.renamed, o.others)
	}
	if o.implied != 2 { // Shibuya and Alice
		t.Fatalf("implied=%d, want 2", o.implied)
	}
}

// After the move, a different OU (a different object) with the same name was created at the original DN.
func TestNewOUCreatedAtTheOldDNAfterTheMove(t *testing.T) {
	src, dst, guids := clonedFrom(t, nestedSource())
	newTop := "OU=Osaka,OU=Users," + base
	moveEntry(dst, tokyoOU, newTop)
	moveEntry(dst, shibuyaOU, "OU=Shibuya,"+newTop)
	moveEntry(dst, alice, "CN=Alice,"+newTop)
	moveEntry(dst, dave, "CN=Dave,OU=Shibuya,"+newTop)
	// Another program recreated an OU with the same name and also created a new user inside it.
	dst.Put(tokyoOU, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Tokyo"}})
	newbie := "CN=Newbie," + tokyoOU
	userAt(dst, newbie, "newbie")

	diffs, sum := diffWith(t, src, dst, guids)
	got := map[string]string{}
	for _, d := range diffs {
		got[d.DN] = string(d.Kind)
	}
	// The original OU that moved is RENAMED. The different OU at the original DN and the new user inside it are reported as not on the source.
	if got[tokyoOU] != "RENAMED" && got[tokyoOU] != "ONLY_TARGET" {
		t.Fatalf("got %v", got)
	}
	var renamedTop, newOU, newUser bool
	for _, d := range diffs {
		switch {
		case d.Kind == diff.Renamed && d.DN == tokyoOU && d.TargetDN == newTop:
			renamedTop = true
		case d.Kind == diff.OnlyTarget && dn.Equal(d.DN, tokyoOU):
			newOU = true
		case d.Kind == diff.OnlyTarget && dn.Equal(d.DN, newbie):
			newUser = true
		}
	}
	if !renamedTop || !newOU || !newUser || len(diffs) != 3 {
		t.Fatalf("want RENAMED(Tokyo→Osaka), ONLY_TARGET(new Tokyo), ONLY_TARGET(Newbie); got %v", diffs)
	}
	if sum.Implied != 3 { // Shibuya, Alice and Dave merely moved with the original OU
		t.Fatalf("implied=%d", sum.Implied)
	}
}

// A user was deleted and a different user (different GUID) was created at the same DN. Same DN, but a different object.
// Even for a different object, differences from the source attributes are reported.
func TestUserDeletedAndRecreatedAtTheSameDNIsReportedAsReplacedWithItsAttributeDifferences(t *testing.T) {
	src, dst, guids := clonedWithMapping(t)
	attrs := map[string][]string{}
	for k, v := range dst.Lookup(alice).Attrs {
		attrs[k] = append([]string(nil), v...)
	}
	delete(attrs, "objectGUID") // recreated, so a new GUID is assigned
	attrs["title"] = []string{"Recreated by another program"}
	dst.Delete(alice)
	dst.Put(alice, attrs)

	diffs, sum := diffWith(t, src, dst, guids)
	if len(diffs) != 2 || sum.Differences[diff.Replaced] != 1 || sum.Differences[diff.Differ] != 1 {
		t.Fatalf("want REPLACED + DIFF(title), got %s: %+v", kindsOf(diffs), diffs)
	}
	for _, d := range diffs {
		if !dn.Equal(d.DN, alice) || (d.Kind == diff.Differ && d.Attr != "title") {
			t.Fatalf("%+v", d)
		}
	}
}

// If it was recreated with identical attributes, only REPLACED is reported (it is still a different object).
func TestReplacedObjectWithIdenticalAttributesShowsOnlyReplaced(t *testing.T) {
	src, dst, guids := clonedWithMapping(t)
	attrs := map[string][]string{}
	for k, v := range dst.Lookup(alice).Attrs {
		attrs[k] = append([]string(nil), v...)
	}
	delete(attrs, "objectGUID")
	dst.Delete(alice)
	dst.Put(alice, attrs)

	diffs, _ := diffWith(t, src, dst, guids)
	if len(diffs) != 1 || diffs[0].Kind != diff.Replaced {
		t.Fatalf("got %s", kindsOf(diffs))
	}
}

// When AD renames or moves an object, it automatically rewrites the references to it (member / manager, etc.) to the new DN.
// This reproduces that situation.
func followRename(dst *fakedir.Dir, oldDN, newDN string) {
	for _, e := range dst.Entries {
		for _, attr := range []string{"member", "manager", "managedBy"} {
			vals := e.Attrs[attr]
			for i, v := range vals {
				if dn.Equal(v, oldDN) {
					vals[i] = newDN
				}
			}
		}
	}
}

func TestReferencesToARenamedObjectAreNotReportedAsDifferences(t *testing.T) {
	src, dst, guids := clonedWithMapping(t)
	renamed := `CN=Doe\, Robert,CN=Staff,OU=Users,` + base // changed the RDN of bob
	moveEntry(dst, bob, renamed)
	followRename(dst, bob, renamed) // alice manager and the member of group eng now point at the new DN

	diffs, _ := diffWith(t, src, dst, guids)
	if len(diffs) != 1 || diffs[0].Kind != diff.Renamed || diffs[0].DN != bob {
		t.Fatalf("references that merely follow a rename must not be differences, got %s: %+v", kindsOf(diffs), diffs)
	}
}

func TestARealReferenceDifferenceIsStillReportedNextToARename(t *testing.T) {
	src, dst, guids := clonedWithMapping(t)
	renamed := `CN=Doe\, Robert,CN=Staff,OU=Users,` + base
	moveEntry(dst, bob, renamed)
	followRename(dst, bob, renamed)
	// A genuine change: another program removed alice from the group.
	var kept []string
	for _, v := range dst.Lookup(eng).Attrs["member"] {
		if !dn.Equal(v, alice) {
			kept = append(kept, v)
		}
	}
	dst.Lookup(eng).Attrs["member"] = kept

	diffs, _ := diffWith(t, src, dst, guids)
	var member *diff.Difference
	renames := 0
	for i := range diffs {
		switch {
		case diffs[i].Kind == diff.Renamed:
			renames++
		case diffs[i].Kind == diff.Differ && diffs[i].Attr == "member":
			member = &diffs[i]
		}
	}
	if renames != 1 || member == nil || len(diffs) != 2 {
		t.Fatalf("want RENAMED + the real member difference, got %s: %+v", kindsOf(diffs), diffs)
	}
	if len(member.OnlySource) != 1 || !dn.Equal(member.OnlySource[0], alice) || len(member.OnlyTarget) != 0 {
		t.Fatalf("only alice is missing, and the renamed bob must not show up as a difference: %+v", member)
	}
}

func TestReferencesToAnObjectMovedWithItsOUAreFollowedToo(t *testing.T) {
	src, dst, guids := clonedWithMapping(t)
	oldOU, newOU := "OU=Tokyo,OU=Users,"+base, "OU=Osaka,OU=Users,"+base
	moveEntry(dst, oldOU, newOU)
	movedAlice := "CN=Alice," + newOU
	moveEntry(dst, alice, movedAlice)
	followRename(dst, alice, movedAlice)

	diffs, sum := diffWith(t, src, dst, guids)
	if len(diffs) != 1 || diffs[0].DN != oldOU || sum.Implied != 1 {
		t.Fatalf("only the OU is RENAMED; references to alice follow her: got %s: %+v", kindsOf(diffs), diffs)
	}
}

func TestWithoutAMappingReferencesToARenamedObjectLookDifferent(t *testing.T) {
	// Without a mapping there is no way to know about the rename. Same behavior as before (the reference is reported as different).
	src, dst, _ := clonedWithMapping(t)
	renamed := `CN=Doe\, Robert,CN=Staff,OU=Users,` + base
	moveEntry(dst, bob, renamed)
	followRename(dst, bob, renamed)
	diffs, _ := diffWith(t, src, dst, nil)
	if len(diffs) < 3 {
		t.Fatalf("expected ONLY_SOURCE + ONLY_TARGET + reference differences, got %s", kindsOf(diffs))
	}
}

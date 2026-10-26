package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/plan"
)

const (
	leeOne = "CN=Lee Ann,OU=Users," + base
	leeTwo = "CN=Lee  Ann,OU=Users," + base // two spaces: a name Samba takes as the one above
)

// collapsingWorld is a target that takes names differing in consecutive spaces as the same, as Samba does, and a
// source holding two users so named, both in a group. echo makes the target answer a read with the DN asked for,
// its own in distinguishedName, as Windows does for the names it takes as the same.
func collapsingWorld(echo bool) *world {
	w := newWorld()
	w.dst.Fold = func(k string) string { return strings.Join(strings.Fields(k), " ") }
	w.dst.EchoDN = echo
	user := []string{"top", "person", "organizationalPerson", "user"}
	w.src.Put(leeOne, map[string][]string{"objectClass": user, "cn": {"Lee Ann"}, "sAMAccountName": {"lee1"}, "title": {"one"}})
	w.src.Put(leeTwo, map[string][]string{"objectClass": user, "cn": {"Lee  Ann"}, "sAMAccountName": {"lee2"}, "title": {"two"}})
	w.src.Put("CN=Team,OU=Users,"+base, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Team"}, "sAMAccountName": {"team"},
		"member": {leeOne, leeTwo}})
	return w
}

// An entry whose name the target takes as another entry's is not added: writing it would overwrite that one. clone
// says which in a warning and lists it in its summary, leaves out the references naming it, and does the same on a
// second run; diff reports it as NAME_TAKEN.
func TestAnEntryWhoseNameTheTargetTakesAsAnothersIsNotWritten(t *testing.T) {
	for name, echo := range map[string]bool{"stored DN": false, "DN asked for": true} {
		t.Run(name, func(t *testing.T) { nameTaken(t, echo) })
	}
}

func nameTaken(t *testing.T, echo bool) {
	ctx := context.Background()
	w := collapsingWorld(echo)
	s := w.openWith(t, "")
	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if len(rep.NameTaken) != 1 {
		t.Fatalf("name taken: %+v\n%s", rep.NameTaken, log.String())
	}
	added, skipped := rep.NameTaken[0].TargetDN, rep.NameTaken[0].DN
	held := w.dst.Lookup(added)
	if held == nil || held.DN != added {
		t.Fatalf("the entry added: %+v", held)
	}
	want := map[string]string{leeOne: "lee1", leeTwo: "lee2"}[added]
	if got := strings.Join(held.Values("sAMAccountName"), ""); got != want {
		t.Fatalf("%s was overwritten with the other's values: %s", added, got)
	}
	if got := w.dst.Lookup("CN=Team,OU=Users," + base).Values("member"); len(got) != 1 || got[0] != added {
		t.Fatalf("the group's members: %v", got)
	}
	if rep.Unwritten["member: names an entry not added: "+clone.WhyNameTaken] != 1 || !strings.Contains(log.String(), "not added: "+skipped) {
		t.Fatalf("%+v\n%s", rep.Unwritten, log.String())
	}
	var sum bytes.Buffer
	rep.WriteSummary(&sum)
	if !strings.Contains(sum.String(), "not added, the target holds another entry under a name it takes as the same: 1\n  "+skipped+"  (the target's: "+added+")") {
		t.Fatalf("summary:\n%s", sum.String())
	}

	log.Reset()
	if rep, err := s.Clone(ctx, false, &log, &log); err != nil || rep.Added+rep.Updated != 0 || len(rep.NameTaken) != 1 {
		t.Fatalf("a second run: %v %+v\n%s", err, rep, log.String())
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitDiff || !strings.Contains(out.String(), "NAME_TAKEN  "+skipped) ||
		!strings.Contains(out.String(), "NAME_TAKEN  : 1") {
		t.Fatalf("diff (%d, %v):\n%s", code, err, out.String())
	}
}

// The cloned entry renamed on the target to a name the target takes as its own: diff reports the rename, and clone
// takes it as the same entry (its marker says so), writing nothing.
func TestAnEntryRenamedToANameTheTargetTakesAsTheSameIsRenamed(t *testing.T) {
	for name, echo := range map[string]bool{"stored DN": false, "DN asked for": true} {
		t.Run(name, func(t *testing.T) { renamedToTheSameName(t, echo) })
	}
}

func renamedToTheSameName(t *testing.T, echo bool) {
	ctx := context.Background()
	w := collapsingWorld(echo)
	w.src.Delete(leeOne)
	w.src.Lookup("CN=Team,OU=Users," + base).Attrs["member"] = []string{leeTwo}
	s := w.openWith(t, "")
	var log bytes.Buffer
	if _, err := s.Clone(ctx, false, &log, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	e := w.dst.Lookup(leeTwo)
	e.DN, e.Attrs["cn"] = leeOne, []string{"Lee Ann"}

	var out bytes.Buffer
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitDiff || !strings.Contains(out.String(), "RENAMED") ||
		strings.Contains(out.String(), "NAME_TAKEN") {
		t.Fatalf("diff (%d, %v):\n%s", code, err, out.String())
	}
	log.Reset()
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil || len(rep.NameTaken) != 0 || rep.Added != 0 {
		t.Fatalf("clone after the rename: %v %+v\n%s", err, rep, log.String())
	}
}

// An OU whose name the target takes as another OU's is not added, nor what is below it: written, the entries below
// would go into the other OU, which the target takes their parent's DN to name.
func TestWhatIsBelowAnEntryWhoseNameIsTakenIsNotAdded(t *testing.T) {
	for name, echo := range map[string]bool{"stored DN": false, "DN asked for": true} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			w := newWorld()
			w.dst.Fold = func(k string) string { return strings.Join(strings.Fields(k), " ") }
			w.dst.EchoDN = echo
			one, two := "OU=Team A,"+base, "OU=Team  A,"+base
			user := []string{"top", "person", "organizationalPerson", "user"}
			for i, ou := range []string{one, two} {
				w.src.Put(ou, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {strings.TrimPrefix(strings.Split(ou, ",")[0], "OU=")}})
				w.src.Put("CN=Member"+string(rune('1'+i))+","+ou, map[string][]string{"objectClass": user, "cn": {"Member" + string(rune('1'+i))},
					"sAMAccountName": {"member" + string(rune('1'+i))}})
			}
			s := w.openWith(t, "")
			var log bytes.Buffer
			rep, err := s.Clone(ctx, false, &log, &log)
			if err != nil {
				t.Fatalf("%v\n%s", err, log.String())
			}
			if len(rep.NameTaken) != 1 || len(rep.Refused) != 1 || !strings.Contains(rep.Refused[0].Why, "below "+rep.NameTaken[0].DN+", not added") {
				t.Fatalf("name taken %+v, refused %+v\n%s", rep.NameTaken, rep.Refused, log.String())
			}
			below := 0
			for k := range w.dst.Snapshot() {
				if strings.HasPrefix(k, "cn=member") {
					below++
				}
			}
			if below != 1 {
				t.Fatalf("one member goes in: %d\n%s", below, log.String())
			}
			var out bytes.Buffer
			if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitDiff || !strings.Contains(out.String(), "NAME_TAKEN  : 1") ||
				!strings.Contains(out.String(), "NOT_WRITABLE: 1") {
				t.Fatalf("diff (%d, %v):\n%s", code, err, out.String())
			}
		})
	}
}

// A value naming an entry the target takes as another's is not written, however that entry came to be wanted:
// referenced from outside the scope (taken when it was created for the value), or one the source does not return,
// which a placeholder would stand for (the target answers with the other: counted as a value not written).
func TestAValueNamingAnEntryWhoseNameIsTakenIsNotWritten(t *testing.T) {
	ctx := context.Background()
	w := newWorld()
	w.dst.Fold = func(k string) string { return strings.Join(strings.Fields(k), " ") }
	user := []string{"top", "person", "organizationalPerson", "user"}
	outOne, outTwo := "CN=Out X,OU=Else,"+domain, "CN=Out  X,OU=Else,"+domain
	ghost, ghostTwo := "CN=Ghost A,OU=Users,"+base, "CN=Ghost  A,OU=Users,"+base // the second the source does not return
	w.src.Put("OU=Else,"+domain, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Else"}})
	for i, d := range []string{outOne, outTwo} {
		w.src.Put(d, map[string][]string{"objectClass": user, "cn": {strings.TrimPrefix(strings.Split(d, ",")[0], "CN=")}, "sAMAccountName": {"out" + string(rune('1'+i))}})
	}
	w.src.Put(ghost, map[string][]string{"objectClass": user, "cn": {"Ghost A"}, "sAMAccountName": {"ghost"}})
	team := "CN=Team,OU=Users," + base
	w.src.Put(team, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Team"}, "sAMAccountName": {"team"},
		"member": {outOne, outTwo, ghost, ghostTwo}})
	s := w.openWith(t, "")
	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	members := w.dst.Lookup(team).Values("member")
	if len(members) != 2 || !contains(members, ghost) {
		t.Fatalf("the group's members: %v\nname taken %+v\n%s", members, rep.NameTaken, log.String())
	}
	taken := map[string]bool{}
	for _, n := range rep.NameTaken {
		taken[n.DN] = true
	}
	if !(taken[outOne] || taken[outTwo]) || rep.Unwritten["member: "+plan.WhyNameTaken] != 1 {
		t.Fatalf("name taken %+v, unwritten %+v\n%s", rep.NameTaken, rep.Unwritten, log.String())
	}
	// diff reports the entry, and compares the group's member without the values clone left out.
	var out bytes.Buffer
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitDiff || !strings.Contains(out.String(), "NAME_TAKEN  : 1") ||
		strings.Contains(out.String(), "DIFF        "+team) {
		t.Fatalf("diff (%d, %v):\n%s", code, err, out.String())
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

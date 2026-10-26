package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/clone"
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
	if rep.Unwritten["member: "+clone.WhyNameTaken] != 1 || !strings.Contains(log.String(), "not added: "+skipped) {
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

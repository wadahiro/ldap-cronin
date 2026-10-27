package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/dump"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// An account whose primary group is not Domain Users gets it on the target, by the group's DN: the group outside the
// scope is created, gets its own RID there, and the account is a member first, as AD needs. diff compares the group,
// not the number, and a dump carries it.
func TestThePrimaryGroupIsTheSourcesByItsDN(t *testing.T) {
	w := newWorld()
	contractors := "CN=Contractors,OU=Groups," + domain
	users := "CN=Domain Users,CN=Users," + domain
	w.src.Put("OU=Groups,"+domain, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Groups"}})
	w.src.Put("CN=Users,"+domain, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Users"}})
	w.src.Put(contractors, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Contractors"}, "sAMAccountName": {"contractors"},
		"objectSid": {fakedir.SID("S-1-5-21-1-2-3-1105")}})
	w.src.Put(users, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Domain Users"}, "isCriticalSystemObject": {"TRUE"},
		"objectSid": {fakedir.SID("S-1-5-21-1-2-3-513")}})
	w.src.Lookup(alice).Attrs["primaryGroupID"] = []string{"1105"}
	w.dst.SIDs = "7-8-9"
	w.dst.PrimaryGroups = true
	w.dst.Put("CN=Users,"+domain, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Users"}})
	w.dst.Put(users, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Domain Users"}, "isCriticalSystemObject": {"TRUE"},
		"objectSid": {fakedir.SID("S-1-5-21-7-8-9-513")}})

	s := w.open(t, "mode = \"off\"")
	ctx := context.Background()
	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatal(err)
	}
	g := w.dst.Lookup(contractors)
	if rep.PrimaryGroups != 1 || g == nil {
		t.Fatalf("%+v\n%s", rep, log.String())
	}
	rid, _ := profile.AD.PrimaryGroup.RID(*g)
	a := w.dst.Lookup(alice)
	if got := strings.Join(a.Values("primaryGroupID"), ""); got != rid || rid == "1105" {
		t.Fatalf("alice's primary group: %q, the target's Contractors is %q", got, rid)
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitSame {
		t.Fatalf("the same group by DN, another RID (%d, %v):\n%s", code, err, out.String())
	}
	// The group itself is compared too: no reference names it and no memberOf lists it.
	g.Attrs["sAMAccountName"] = []string{"renamed"}
	out.Reset()
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitDiff || !strings.Contains(out.String(), contractors) {
		t.Fatalf("the primary group outside the scope is compared (%d, %v):\n%s", code, err, out.String())
	}
	g.Attrs["sAMAccountName"] = []string{"contractors"}
	a.Attrs["primaryGroupID"] = []string{"513"}
	out.Reset()
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitDiff || !strings.Contains(out.String(), "Domain Users") {
		t.Fatalf("another primary group shows, as the group (%d, %v):\n%s", code, err, out.String())
	}

	var dumped bytes.Buffer
	if _, err := dump.Write(ctx, w.src, profile.AD, dump.Options{BaseDNs: []string{base}, Server: "ldaps://src:636", Version: "test"}, &dumped); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dumped.String(), "dn: "+contractors+"\n") {
		t.Error("the dump lacks the primary group")
	}
}

// The target refuses a member value naming an account whose primary group the group is (Samba stops the run; the
// account is a member through primaryGroupID): such values are not written, whether the group is outside the scope
// (Domain Users) or in it, nor that of an account whose primary group the source lacks (an old dump), which keeps
// Domain Users. check lists them and that account, clone counts them and warns of it first; diff does not compare
// them.
func TestAMemberThroughThePrimaryGroupIsNotWritten(t *testing.T) {
	ctx := context.Background()
	w := newWorld()
	users := "CN=Domain Users,CN=Users," + domain
	bob := "CN=Bob,OU=Users," + base
	carol := "CN=Carol,OU=Users," + base
	staff := "CN=Staff,OU=Users," + base
	user := []string{"top", "person", "organizationalPerson", "user"}
	w.src.Put("CN=Users,"+domain, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Users"}})
	w.src.Put(users, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Domain Users"}, "isCriticalSystemObject": {"TRUE"},
		"objectSid": {fakedir.SID("S-1-5-21-1-2-3-513")}, "member": {alice, bob}})
	w.src.Lookup(alice).Attrs["memberOf"] = []string{users}
	w.src.Put(bob, map[string][]string{"objectClass": user, "cn": {"Bob"}, "sAMAccountName": {"bob"}, "userAccountControl": {"512"},
		"primaryGroupID": {"1199"}, "memberOf": {users}})
	w.src.Put(staff, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Staff"}, "sAMAccountName": {"staff"},
		"objectSid": {fakedir.SID("S-1-5-21-1-2-3-1300")}, "member": {alice, carol}})
	w.src.Put(carol, map[string][]string{"objectClass": user, "cn": {"Carol"}, "sAMAccountName": {"carol"}, "userAccountControl": {"512"},
		"primaryGroupID": {"1300"}})
	w.dst.SIDs = "7-8-9"
	w.dst.Put("CN=Users,"+domain, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Users"}})
	w.dst.Put(users, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Domain Users"}, "isCriticalSystemObject": {"TRUE"},
		"objectSid": {fakedir.SID("S-1-5-21-7-8-9-513")}})
	for _, d := range []*fakedir.Dir{w.src, w.dst} { // the schema pairing memberOf with member: what finds the holders
		withClasses(d, nil)
		for name, link := range map[string]string{"member": "2", "memberOf": "3"} {
			d.Put("CN="+name+","+schemaNC, map[string][]string{"objectClass": {"attributeSchema"}, "cn": {name}, "lDAPDisplayName": {name},
				"attributeID": {"1.9." + name}, "attributeSyntax": {"2.5.5.1"}, "linkID": {link}})
		}
	}
	w.dst.Put("", map[string][]string{"schemaNamingContext": {schemaNC}, "vendorName": {samba}, "defaultNamingContext": {domain}})
	w.dst.PrimaryGroups = true
	s := w.open(t, "mode = \"off\"")
	const why = "names an account whose primary group the group is, a member through primaryGroupID: the target refuses it"

	var out bytes.Buffer
	if _, err := s.Check(ctx, CheckOptions{Config: "c.toml"}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"member values clone will not write, the target refuses them: 3", "  " + alice + " in " + users, "  " + bob + " in " + users,
		"  " + carol + " in " + staff, "accounts whose primary group the source lacks: 1", "  " + bob + " (primaryGroupID 1199)"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("check lacks %q:\n%s", want, out.String())
		}
	}

	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if got := w.dst.Lookup(users).Values("member"); len(got) != 0 {
		t.Fatalf("Domain Users' members: %v\n%s", got, log.String())
	}
	if got := w.dst.Lookup(staff).Values("member"); len(got) != 1 || got[0] != alice {
		t.Fatalf("Staff's members: %v\n%s", got, log.String())
	}
	if n := rep.Unwritten["member: "+why]; n != 3 {
		t.Fatalf("unwritten %+v\n%s", rep.Unwritten, log.String())
	}
	if !strings.Contains(log.String(), "1 accounts name a primary group the source lacks") || !strings.Contains(log.String(), bob+" (1199)") {
		t.Fatalf("log:\n%s", log.String())
	}
	// The groups are the same; Bob is not, his primary group being one the source lacks.
	out.Reset()
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitDiff || !strings.Contains(out.String(), "DIFF        "+bob) ||
		!strings.Contains(out.String(), "DIFF        : 1") || !strings.Contains(out.String(), "member: "+why) {
		t.Fatalf("diff (%d, %v):\n%s", code, err, out.String())
	}
}

// A well-known group is told by its RID, not its DN: the source's Domain Admins moved out of CN=Users is the
// target's own in CN=Users. Its members of the scope are given to it there, an account whose primary group it is
// gets it, and a value of the scope naming it names the target's; clone says so once, a second clone writes nothing,
// and diff finds the same.
func TestAWellKnownGroupMovedOnTheSourceIsTheTargetsOfItsRID(t *testing.T) {
	ctx := context.Background()
	w := newWorld()
	moved := "CN=Domain Admins,OU=Admin Groups," + domain
	admins := "CN=Domain Admins,CN=Users," + domain
	bob := "CN=Bob,OU=Users," + base
	team := "CN=Team,OU=Users," + base
	user := []string{"top", "person", "organizationalPerson", "user"}
	w.src.Put("OU=Admin Groups,"+domain, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Admin Groups"}})
	w.src.Put(moved, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Domain Admins"}, "isCriticalSystemObject": {"TRUE"},
		"objectSid": {fakedir.SID("S-1-5-21-1-2-3-512")}, "member": {bob}})
	w.src.Put(bob, map[string][]string{"objectClass": user, "cn": {"Bob"}, "sAMAccountName": {"bob"}, "userAccountControl": {"512"},
		"memberOf": {moved}})
	w.src.Lookup(alice).Attrs["primaryGroupID"] = []string{"512"}
	w.src.Put(team, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Team"}, "sAMAccountName": {"team"}, "member": {moved}})
	w.dst.SIDs = "7-8-9"
	w.dst.PrimaryGroups = true
	w.dst.Put("CN=Users,"+domain, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Users"}})
	w.dst.Put(admins, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Domain Admins"}, "isCriticalSystemObject": {"TRUE"},
		"objectSid": {fakedir.SID("S-1-5-21-7-8-9-512")}})
	for _, d := range []*fakedir.Dir{w.src, w.dst} { // the schema pairing memberOf with member: what finds the holders
		withClasses(d, nil)
		for name, link := range map[string]string{"member": "2", "memberOf": "3"} {
			d.Put("CN="+name+","+schemaNC, map[string][]string{"objectClass": {"attributeSchema"}, "cn": {name}, "lDAPDisplayName": {name},
				"attributeID": {"1.9." + name}, "attributeSyntax": {"2.5.5.1"}, "linkID": {link}})
		}
	}
	s := w.open(t, "mode = \"off\"")

	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if w.dst.Lookup(moved) != nil || len(rep.Unheld) != 0 || len(rep.Unwritten) != 0 || rep.BuiltinGroups != 1 {
		t.Fatalf("unheld %+v, unwritten %+v\n%s", rep.Unheld, rep.Unwritten, log.String())
	}
	if got := w.dst.Lookup(admins).Values("member"); len(got) != 1 || got[0] != bob {
		t.Fatalf("the target's Domain Admins: %v\n%s", got, log.String())
	}
	if got := strings.Join(w.dst.Lookup(alice).Values("primaryGroupID"), ""); got != "512" {
		t.Fatalf("alice's primary group: %q\n%s", got, log.String())
	}
	if got := w.dst.Lookup(team).Values("member"); len(got) != 1 || got[0] != admins {
		t.Fatalf("Team's members: %v\n%s", got, log.String())
	}
	if strings.Count(log.String(), moved+" is the target's "+admins) != 1 || strings.Contains(log.String(), "dump again") {
		t.Fatalf("log:\n%s", log.String())
	}
	log.Reset()
	if rep, err := s.Clone(ctx, false, &log, &log); err != nil || rep.Added+rep.Updated != 0 {
		t.Fatalf("a second run: %v %+v\n%s", err, rep, log.String())
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitSame {
		t.Fatalf("diff (%d, %v):\n%s", code, err, out.String())
	}
}

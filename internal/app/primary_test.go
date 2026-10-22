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
	a.Attrs["primaryGroupID"] = []string{"513"}
	out.Reset()
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitDiff || !strings.Contains(out.String(), "Domain Users") {
		t.Fatalf("another primary group shows, as the group (%d, %v):\n%s", code, err, out.String())
	}

	var dumped bytes.Buffer
	if _, err := dump.Write(ctx, w.src, profile.AD, dump.Options{BaseDN: base, Server: "ldaps://src:636", Version: "test"}, &dumped); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dumped.String(), "dn: "+contractors+"\n") {
		t.Error("the dump lacks the primary group")
	}
}

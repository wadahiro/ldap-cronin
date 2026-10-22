package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/dump"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// holdersWorld is a source whose user Alice (in the scope) is a member of a group of another OU and of Domain
// Admins, with the schema pairing memberOf with member; the target holds its own Domain Admins.
func holdersWorld() (*world, string, string) {
	w := newWorld()
	vpn := "CN=VPN,OU=Groups," + domain
	admins := "CN=Domain Admins,CN=Users," + domain
	bob := "CN=Bob,OU=Elsewhere," + domain
	w.src.Put("OU=Groups,"+domain, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Groups"}})
	w.src.Put("OU=Elsewhere,"+domain, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Elsewhere"}})
	w.src.Put("CN=Users,"+domain, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Users"}})
	w.src.Put(bob, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {"Bob"},
		"sAMAccountName": {"bob"}, "userAccountControl": {"512"}, "memberOf": {vpn}})
	w.src.Put(vpn, map[string][]string{"objectClass": {"top", "group"}, "cn": {"VPN"}, "sAMAccountName": {"vpn"},
		"description": {"remote access"}, "member": {alice, bob}})
	w.src.Put(admins, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Domain Admins"}, "sAMAccountName": {"Domain Admins"},
		"isCriticalSystemObject": {"TRUE"}, "member": {"CN=Administrator,CN=Users," + domain, alice}})
	w.src.Lookup(alice).Attrs["memberOf"] = []string{vpn, admins}
	w.dst.Put("CN=Users,"+domain, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Users"}})
	w.dst.Put(admins, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Domain Admins"}, "isCriticalSystemObject": {"TRUE"},
		"member": {"CN=Administrator,CN=Users," + domain}})
	for _, d := range []*fakedir.Dir{w.src, w.dst} {
		withClasses(d, nil)
		for name, link := range map[string]string{"member": "2", "memberOf": "3"} {
			d.Put("CN="+name+","+schemaNC, map[string][]string{"objectClass": {"attributeSchema"}, "cn": {name}, "lDAPDisplayName": {name},
				"attributeID": {"1.9." + name}, "attributeSyntax": {"2.5.5.1"}, "linkID": {link}})
		}
	}
	return w, vpn, admins
}

// A membership is the group's value: a group of another OU holding a user of the scope is created and given that
// member (and not its others, nor its own references), Domain Admins of the target is given it too, and diff
// compares those values alone; check says so before.
func TestGroupsOutsideTheScopeAreGivenTheirMembersOfIt(t *testing.T) {
	w, vpn, admins := holdersWorld()
	s := w.open(t, "mode = \"off\"")
	ctx := context.Background()
	var report bytes.Buffer
	if _, err := s.Check(ctx, CheckOptions{Config: "c.toml"}, &report); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"groups holding entries of base_dn that clone gives those members", "built-in (the target's own get the members)  1", "outside base_dn (clone creates them)         1"} {
		if !strings.Contains(report.String(), want) {
			t.Errorf("check lacks %q:\n%s", want, report.String())
		}
	}

	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OutsideGroups != 1 || rep.BuiltinGroups != 1 {
		t.Fatalf("%+v\n%s", rep, log.String())
	}
	g := w.dst.Lookup(vpn)
	if g == nil || strings.Join(g.Values("member"), "|") != alice || strings.Join(g.Values("description"), "") != "remote access" {
		t.Fatalf("the group of another OU: %+v", g)
	}
	if got := strings.Join(w.dst.Lookup(admins).Values("member"), "|"); got != "CN=Administrator,CN=Users,"+domain+"|"+alice {
		t.Fatalf("Domain Admins: %s", got)
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitSame || !strings.Contains(out.String(), "groups outside the scope holding its entries compared: 2") {
		t.Fatalf("right after the clone (%d, %v):\n%s", code, err, out.String())
	}
	w.dst.Lookup(admins).Attrs["member"] = []string{"CN=Administrator,CN=Users," + domain}
	out.Reset()
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitDiff || !strings.Contains(out.String(), "Domain Admins") {
		t.Fatalf("a membership removed on the target shows (%d, %v):\n%s", code, err, out.String())
	}

	// A dump carries both groups, with every member, so a clone of it gives the same.
	var dumped bytes.Buffer
	if _, err := dump.Write(ctx, w.src, profile.AD, dump.Options{BaseDN: base, Server: "ldaps://src:636", Version: "test"}, &dumped); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"dn: " + vpn + "\n", "dn: " + admins + "\n", "# holders: "} {
		if !strings.Contains(dumped.String(), want) {
			t.Errorf("the dump lacks %q", want)
		}
	}
}

// Each can be turned off: the groups are then left as they are, and counted.
func TestGroupsOutsideTheScopeCanBeLeftAlone(t *testing.T) {
	w, vpn, admins := holdersWorld()
	s := w.openWith(t, "outside_groups = \"skip\"\nbuiltin_groups = \"skip\"\n[mapping]\nmode = \"off\"\n")
	ctx := context.Background()
	rep, err := s.Clone(ctx, false, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OutsideGroups+rep.BuiltinGroups != 0 || rep.Unheld[plan.WhyHolderSkipped] != 1 || rep.Unheld[plan.WhyBuiltinSkipped] != 1 {
		t.Fatalf("%+v", rep)
	}
	if w.dst.Lookup(vpn) != nil || len(w.dst.Lookup(admins).Values("member")) != 1 {
		t.Fatal("left as they are")
	}
	var sum bytes.Buffer
	rep.WriteSummary(&sum)
	if !strings.Contains(sum.String(), "outside_groups = \"skip\"") {
		t.Fatalf("the summary says why:\n%s", sum.String())
	}
}

// A dry-run cannot read the target, and every domain has Domain Admins: its LDIF adds the member, and the group of
// another OU is created.
func TestADryRunGivesTheBuiltinGroupItsMembers(t *testing.T) {
	w, vpn, admins := holdersWorld()
	s := w.open(t, "mode = \"off\"")
	var ldif, log bytes.Buffer
	rep, err := s.Clone(context.Background(), true, &ldif, &log)
	if err != nil {
		t.Fatal(err)
	}
	if rep.BuiltinGroups != 1 || len(rep.Unheld) != 0 {
		t.Fatalf("%+v\n%s", rep, log.String())
	}
	for _, want := range []string{"dn: " + admins + "\nchangetype: modify\nadd: member\nmember: " + alice, "dn: " + vpn + "\nchangetype: add\n"} {
		if !strings.Contains(ldif.String(), want) {
			t.Errorf("the LDIF lacks %q:\n%s", want, ldif.String())
		}
	}
}

package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/dump"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// OU=*,<domain> is every OU right under the domain but the built-in ones: the containers beside them (CN=Users)
// are left out, but for what a reference of the scope names, which is cloned as a referenced object is.
func TestAWildcardBaseIsTheOUsRightUnderIt(t *testing.T) {
	w := newWorld()
	carl, dave := "CN=Carl,CN=Users,"+domain, "CN=Dave,CN=Users,"+domain
	w.src.Put("OU=Sales,"+domain, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Sales"}})
	w.src.Put("OU=Domain Controllers,"+domain, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Domain Controllers"},
		"isCriticalSystemObject": {"TRUE"}})
	w.src.Put("CN=Users,"+domain, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Users"}, "isCriticalSystemObject": {"TRUE"}})
	for _, u := range []string{carl, dave} {
		cn := strings.TrimPrefix(strings.Split(u, ",")[0], "CN=")
		w.src.Put(u, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {cn},
			"sAMAccountName": {strings.ToLower(cn)}, "userAccountControl": {"512"}})
	}
	w.src.Lookup(alice).Attrs["manager"] = []string{carl}
	w.dst.Put("CN=Users,"+domain, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Users"}})

	bases, err := plan.ExpandBases(context.Background(), w.src, "isCriticalSystemObject", []string{"OU=*," + domain})
	if err != nil || strings.Join(bases, "|") != "OU=IDM,"+domain+"|OU=Sales,"+domain {
		t.Fatalf("expanded: %v %v", bases, err)
	}

	s, err := w.tryOpenBase("OU=*,"+domain, "[mapping]\nmode = \"off\"")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if strings.Join(s.Job.BaseDNs, "|") != "OU=IDM,"+domain+"|OU=Sales,"+domain {
		t.Fatalf("the session's base DNs: %v", s.Job.BaseDNs)
	}
	rep, err := s.Clone(context.Background(), false, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if w.dst.Lookup(alice) == nil || w.dst.Lookup(carl) == nil || w.dst.Lookup(dave) != nil || rep.ReferencedKinds["user"] != 1 {
		t.Fatalf("Alice in an OU, Carl her manager in CN=Users, not Dave: %+v", rep)
	}
	if w.dst.Lookup("OU=Sales,"+domain) == nil {
		t.Fatal("the empty OU is cloned too")
	}

	// A dump records the OUs the wildcard stood for.
	var out bytes.Buffer
	if _, err := dump.Write(context.Background(), w.src, profile.AD, dump.Options{BaseDNs: []string{"OU=*," + domain}, Version: "test"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "# base-dn: OU=IDM,"+domain+"\n# base-dn: OU=Sales,"+domain+"\n") {
		t.Fatalf("the dump's header:\n%s", out.String()[:400])
	}
}

package main

import (
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/lab"
)

const (
	nDomain = "DC=ad,DC=example,DC=com"
	nBase   = "OU=IDM," + nDomain
)

func nDir(guid string) *fakedir.Dir {
	d := fakedir.New(nDomain)
	d.Put(nBase, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}, "objectGUID": {guid}})
	return d
}

func TestRealmOfDomainRoot(t *testing.T) {
	if got := realmOf("DC=Corp,DC=Example,DC=LOCAL"); got != "corp.example.local" {
		t.Fatal(got)
	}
}

func TestIdentityIsPreservedOnlyWhenTheBaseObjectHasTheSameGUID(t *testing.T) {
	same, _, err := identityPreserved(nDir("g1"), nDir("g1"), nBase)
	if err != nil || !same {
		t.Fatalf("same GUID: %v %v", same, err)
	}
	same, why, err := identityPreserved(nDir("g1"), nDir("g2"), nBase)
	if err != nil || same || !strings.Contains(why, nBase) {
		t.Fatalf("a different GUID (an LDAP clone) must not enable identity: %v %q %v", same, why, err)
	}
}

func TestIdentityProbeSkipsAnExistingContainerAsBaseDN(t *testing.T) {
	// When base_dn is a container that already exists in the lab, such as CN=Users, its GUID is naturally different.
	users := "CN=Users," + nDomain
	build := func(containerGUID, aliceGUID string) *fakedir.Dir {
		d := fakedir.New(nDomain)
		d.Put(users, map[string][]string{"objectClass": {"top", "container"}, "objectGUID": {containerGUID}})
		d.Put("CN=Alice,"+users, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"},
			"objectCategory": {"person"}, "objectGUID": {aliceGUID}})
		return d
	}
	same, why, err := identityPreserved(build("c1", "a1"), build("c2", "a1"), users)
	if err != nil || !same {
		t.Fatalf("the child decides: %v %q %v", same, why, err)
	}
	same, _, _ = identityPreserved(build("c1", "a1"), build("c1", "a2"), users)
	if same {
		t.Fatal("a different child GUID must not enable identity")
	}
}

func TestCheckSameDomain(t *testing.T) {
	info := lab.NativeInfo{Base: "dc=ad,dc=example,dc=com", DomainSID: "S-1-5-21-1-2-3", DomainGUID: "AAAAAAAA-0000-0000-0000-000000000000"}
	if err := checkSameDomain(info, nDomain, "S-1-5-21-1-2-3", "aaaaaaaa-0000-0000-0000-000000000000"); err != nil {
		t.Fatal(err)
	}
	err := checkSameDomain(info, nDomain, "S-1-5-21-9-9-9", "aaaaaaaa-0000-0000-0000-000000000000")
	if err == nil || !strings.Contains(err.Error(), "domain SID") || !strings.Contains(err.Error(), "--like-source") {
		t.Fatalf("a different SID must be refused with a hint: %v", err)
	}
}

func TestMergeLikeLetsExplicitFlagsWin(t *testing.T) {
	base := lab.Settings{Realm: "src.example.com", NetBIOS: "SRC", DomainSID: "S-1-5-21-1-2-3", DomainGUID: "g"}
	got := mergeLike(base, lab.Settings{NetBIOS: "LAB", LDAPPort: 1, LDAPSPort: 2, AdminPassword: "pw"})
	if got.Realm != "src.example.com" || got.NetBIOS != "LAB" || got.DomainSID != "S-1-5-21-1-2-3" || got.LDAPPort != 1 || got.AdminPassword != "pw" {
		t.Fatalf("%+v", got)
	}
}

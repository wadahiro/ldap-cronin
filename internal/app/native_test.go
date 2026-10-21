package app

import (
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/lab"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

func TestCheckSameDomain(t *testing.T) {
	info := lab.NativeInfo{Base: "dc=ad,dc=example,dc=com", DomainSID: "S-1-5-21-1-2-3", DomainGUID: "AAAAAAAA-0000-0000-0000-000000000000"}
	src := profile.Domain{Root: "DC=ad,DC=example,DC=com", SID: "S-1-5-21-1-2-3", GUID: "aaaaaaaa-0000-0000-0000-000000000000"}
	if err := checkSameDomain(info, src); err != nil {
		t.Fatal(err)
	}
	src.SID = "S-1-5-21-9-9-9"
	err := checkSameDomain(info, src)
	if err == nil || !strings.Contains(err.Error(), "domain SID") || !strings.Contains(err.Error(), "lab up --config") {
		t.Fatalf("a different SID must be refused with a hint: %v", err)
	}
}

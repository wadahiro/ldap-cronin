package dn

import (
	"reflect"
	"testing"
)

func TestSplitKeepsEscapedCommaInsideRDN(t *testing.T) {
	got := Split(`CN=Doe\, John,OU=営業部,DC=ad,DC=example,DC=com`)
	want := []string{`CN=Doe\, John`, "OU=営業部", "DC=ad", "DC=example", "DC=com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParentOfEscapedCommaRDN(t *testing.T) {
	if got := Parent(`CN=Doe\, John,OU=A,DC=x`); got != "OU=A,DC=x" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeIgnoresCaseAndEscapeStyle(t *testing.T) {
	if !Equal(`cn=Doe\, John,ou=a,dc=X`, `CN=Doe\2C John,OU=A,DC=x`) {
		t.Fatal("expected equal")
	}
}

func TestDomainRootAndAncestors(t *testing.T) {
	d := "CN=u,CN=Staff,OU=Users,OU=IDM,DC=ad,DC=example,DC=com"
	root := DomainRoot(d)
	if root != "DC=ad,DC=example,DC=com" {
		t.Fatalf("root %q", root)
	}
	want := []string{"CN=Staff,OU=Users,OU=IDM,DC=ad,DC=example,DC=com", "OU=Users,OU=IDM,DC=ad,DC=example,DC=com", "OU=IDM,DC=ad,DC=example,DC=com"}
	if got := Ancestors(d, root); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
}

func TestIsDescendantRejectsSelfAndSiblingsWithSharedSuffix(t *testing.T) {
	if IsDescendant("OU=A,DC=x", "OU=A,DC=x") {
		t.Fatal("self is not a descendant")
	}
	if IsDescendant("OU=XA,DC=x", "OU=A,DC=x") {
		t.Fatal("suffix match without RDN boundary")
	}
	if !IsDescendant("CN=u,ou=a,dc=X", "OU=A,DC=x") {
		t.Fatal("expected descendant")
	}
}

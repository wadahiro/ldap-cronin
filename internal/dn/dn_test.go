package dn

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
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

// A value holding an escaped comma is one RDN: it neither equals the DN with a real comma there nor lies below the
// RDN that follows the comma.
func TestAnEscapedCommaNeverReadsAsAnRDNBoundary(t *testing.T) {
	escaped, plain := `CN=x\,OU=Users,DC=ad`, `CN=x,OU=Users,DC=ad`
	if Equal(escaped, plain) {
		t.Fatalf("%q and %q are different DNs", escaped, plain)
	}
	if IsDescendant(escaped, "OU=Users,DC=ad") {
		t.Fatalf("%q is below DC=ad, not OU=Users", escaped)
	}
	if !IsDescendant(escaped, "DC=ad") || !IsDescendant(plain, "OU=Users,DC=ad") {
		t.Fatal("real descendants must still be found")
	}
	if !Equal(`CN=Doe\, Bob,DC=ad`, `cn=doe\2c bob,dc=AD`) {
		t.Fatal("escaping styles and case must still compare equal")
	}
	if Equal(`CN=a\+b,DC=ad`, `CN=a+SN=b,DC=ad`) {
		t.Fatal("an escaped plus is not a multi-valued RDN")
	}
}

var attrType = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]*|[0-9]+(\.[0-9]+)*)$`)

// The DN operations agree with each other for any DN the parser accepts: normalizing twice changes nothing, an entry
// is below its parent and every ancestor, and a normalized DN splits into as many RDNs as the original.
func FuzzDNOperationsAgree(f *testing.F) {
	for _, s := range []string{
		`CN=Doe\, Bob,OU=Users,DC=ad,DC=example`, `CN=x\,OU=Users,DC=ad`, `cn=a+sn=b,dc=x`, `CN=\#lead,DC=x`,
		`CN=trail\ ,DC=x`, `CN=日本語,OU=東京,DC=x`, `CN=a\2Cb,DC=x`, `uid=q\"uote,ou=People,dc=example,dc=org`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		parsed, err := ldap.ParseDN(s)
		if err != nil || strings.TrimSpace(s) == "" {
			return
		}
		for _, rdn := range parsed.RDNs {
			for _, a := range rdn.Attributes {
				if !attrType.MatchString(strings.TrimSpace(a.Type)) {
					return // servers only produce names and OIDs as attribute types
				}
			}
		}
		if len(Split(s)) != len(parsed.RDNs) {
			return // the obsolete ";" separator: servers return DNs with ","
		}
		n := Normalize(s)
		if again := Normalize(n); again != n {
			t.Fatalf("Normalize is not idempotent: %q -> %q -> %q", s, n, again)
		}
		if len(Split(n)) != len(Split(s)) {
			t.Fatalf("RDN count changed: %q (%d) -> %q (%d)", s, len(Split(s)), n, len(Split(n)))
		}
		for p := Parent(s); p != ""; p = Parent(p) {
			if _, err := ldap.ParseDN(p); err != nil {
				return // a parent the parser refuses (e.g. an empty RDN) has no defined order
			}
			if !IsDescendant(s, p) || IsDescendant(p, s) {
				t.Fatalf("%q must be below its ancestor %q and not the reverse", s, p)
			}
		}
		if IsDescendant(s, s) {
			t.Fatalf("%q is not its own descendant", s)
		}
	})
}

// The domain itself has no ancestors below the domain, and an entry outside it none either: never DC=com.
func TestAncestorsStopAtTheDomain(t *testing.T) {
	if got := Ancestors("DC=ad,DC=example,DC=com", "DC=ad,DC=example,DC=com"); len(got) != 0 {
		t.Errorf("the domain itself: %v", got)
	}
	if got := Ancestors("CN=a,OU=b,DC=ad,DC=example,DC=com", "DC=ad,DC=example,DC=com"); len(got) != 1 || got[0] != "OU=b,DC=ad,DC=example,DC=com" {
		t.Errorf("an entry: %v", got)
	}
	if got := Ancestors("CN=a,DC=other,DC=com", "DC=ad,DC=example,DC=com"); len(got) != 0 {
		t.Errorf("outside: %v", got)
	}
}

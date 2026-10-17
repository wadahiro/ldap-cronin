package profile

import (
	"context"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// Definitions as an OpenLDAP server returns them in attributeTypes.
var openLDAPSchema = []string{
	"( 2.5.4.49 NAME 'distinguishedName' DESC 'RFC4519: common supertype of DN attributes' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	"( 2.5.4.31 NAME 'member' DESC 'RFC2256: member of a group' SUP distinguishedName )",
	"( 2.5.4.50 NAME 'uniqueMember' DESC 'RFC2256: unique member of a group' EQUALITY uniqueMemberMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )",
	"( 0.9.2342.19200300.100.1.10 NAME 'manager' DESC 'RFC1274: DN of manager' SUP distinguishedName )",
	"( 2.5.4.32 NAME 'owner' DESC 'RFC2256: owner (of the object)' SUP distinguishedName )",
	"( 2.16.840.1.113730.3.1.2 NAME 'departmentNumber' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	"( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
	"( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC4519: common name(s)' SUP name )",
	"( 1.3.6.1.4.1.250.1.57 NAME 'labeledURI' SINGLE-VALUE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	"( 2.5.4.34 NAME 'seeAlso' SUP distinguishedName )",
	"( 1.2.3 NAME 'primaryOwner' SUP owner SINGLE-VALUE )",
}

func TestDNAttributesAreFoundThroughSupAndSyntax(t *testing.T) {
	refs := dnRefsFromSchema(openLDAPSchema)
	for _, name := range []string{"member", "uniquemember", "manager", "owner", "seealso", "distinguishedname"} {
		if _, ok := refs[name]; !ok {
			t.Errorf("%s must be a DN reference", name)
		}
	}
	for _, name := range []string{"cn", "commonname", "name", "departmentnumber", "labeleduri"} {
		if _, ok := refs[name]; ok {
			t.Errorf("%s must not be a DN reference", name)
		}
	}
	if !refs["primaryowner"] {
		t.Error("a SINGLE-VALUE attribute that inherits the DN syntax through SUP must be single-valued")
	}
	if refs["member"] {
		t.Error("member is multi-valued")
	}
}

func TestParseAttributeTypeWithSeveralNames(t *testing.T) {
	at, ok := parseAttributeType("( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )")
	if !ok || len(at.names) != 2 || at.names[1] != "commonName" || at.sup != "name" {
		t.Fatalf("%+v %v", at, ok)
	}
	if _, ok := parseAttributeType("garbage"); ok {
		t.Fatal("a definition without NAME must be skipped")
	}
}

type namingContexts []string

func (n namingContexts) Walk(context.Context, string, string, []string, func(directory.Entry) error) error {
	return nil
}
func (n namingContexts) Get(ctx context.Context, dnStr string, _ []string) (*directory.Entry, error) {
	if dnStr != "" {
		return nil, nil
	}
	return &directory.Entry{Attrs: map[string][]string{"namingContexts": n}}, nil
}
func (n namingContexts) Add(context.Context, directory.Entry, ...directory.Control) error { return nil }
func (n namingContexts) Replace(context.Context, string, map[string][]string) error       { return nil }
func (n namingContexts) AddValues(context.Context, string, string, []string) error        { return nil }

func TestRootResolvers(t *testing.T) {
	cases := []struct {
		name string
		r    RootResolver
		src  directory.Directory
		base string
		want string
	}{
		{"AD uses the trailing DC run", adRoot{}, namingContexts{}, "OU=IDM,DC=ad,DC=example,DC=com", "DC=ad,DC=example,DC=com"},
		{"longest naming context", namingContextRoot{}, namingContexts{"dc=org", "dc=example,dc=org"}, "ou=IDM,dc=example,dc=org", "dc=example,dc=org"},
		{"o= suffix from namingContexts", namingContextRoot{}, namingContexts{"o=acme"}, "ou=people,o=acme", "o=acme"},
		{"falls back to the DC run", namingContextRoot{}, namingContexts{}, "ou=IDM,dc=example,dc=org", "dc=example,dc=org"},
	}
	for _, c := range cases {
		got, err := c.r.Root(context.Background(), c.src, c.base)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q (%v), want %q", c.name, got, err, c.want)
		}
	}
	if _, err := (namingContextRoot{}).Root(context.Background(), namingContexts{}, "ou=people,o=acme"); err == nil {
		t.Fatal("no way to find the root must ask for root_dn")
	}
	if _, err := (adRoot{}).Root(context.Background(), namingContexts{}, "OU=People,O=acme"); err == nil {
		t.Fatal("an AD base_dn without DC= components must be refused")
	}
}

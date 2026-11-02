package profile

import (
	"context"
	"fmt"
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
		{"base_dn that is an o= naming context", namingContextRoot{}, namingContexts{"dc=org", "o=acme"}, "O=Acme", "o=acme"},
		{"base_dn that is a dc= naming context", namingContextRoot{}, namingContexts{"dc=org", "dc=example,dc=org"}, "dc=example,dc=org", "dc=example,dc=org"},
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

// openLDAPClasses are object classes as OpenLDAP returns them in objectClasses, with the attribute types they name.
var (
	openLDAPClasses = []string{
		"( 2.5.6.0 NAME 'top' DESC 'top of the superclass chain' ABSTRACT MUST objectClass )",
		"( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )",
		"( 2.5.6.7 NAME 'organizationalPerson' DESC 'RFC2256: an organizational person' SUP person STRUCTURAL MAY ( title $ ou ) )",
		"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' DESC 'RFC2798: Internet Organizational Person' SUP organizationalPerson STRUCTURAL MAY ( mail $ uid $ departmentNumber $ 0.9.2342.19200300.100.1.10 ) )",
		"( 1.3.6.1.1.1.2.0 NAME 'posixAccount' DESC 'Abstraction of an account with POSIX attributes' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) MAY ( userPassword $ loginShell $ gecos $ description ) )",
		"( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject' DESC 'RFC4512: extensible object' SUP top AUXILIARY )",
		"( 1.2.3.4 NAME ( 'decoyClass' 'decoy' ) DESC 'says SUP person MUST ( secret ) in its DESC' SUP top STRUCTURAL MAY description )",
	}
	openLDAPTypes = append(append([]string(nil), openLDAPSchema...),
		"( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		"( 2.5.4.4 NAME ( 'sn' 'surname' ) SUP name )",
		"( 2.5.4.35 NAME 'userPassword' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
		"( 2.5.4.20 NAME 'telephoneNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.50{32} )",
		"( 2.5.4.13 NAME 'description' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{1024} )",
		"( 2.5.4.12 NAME 'title' SUP name )",
		"( 2.5.4.11 NAME ( 'ou' 'organizationalUnitName' ) SUP name )",
		"( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'rfc822Mailbox' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} )",
		"( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )",
		"( 1.3.6.1.1.1.1.0 NAME 'uidNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
		"( 1.3.6.1.1.1.1.1 NAME 'gidNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
		"( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
		"( 1.3.6.1.1.1.1.4 NAME 'loginShell' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
		"( 1.3.6.1.1.1.1.2 NAME 'gecos' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
		"( 2.5.18.1 NAME 'createTimestamp' DESC 'RFC4512: time which object was created' EQUALITY generalizedTimeMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		"( 1.3.6.1.1.16.4 NAME 'entryUUID' DESC 'UUID of the entry' EQUALITY UUIDMatch SYNTAX 1.3.6.1.1.16.1 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		"( 1.2.840.113556.1.2.102 NAME 'memberOf' DESC 'Group that the entry belongs to' SYNTAX '1.3.6.1.4.1.1466.115.121.1.12' EQUALITY distinguishedNameMatch USAGE dSAOperation X-ORIGIN 'iPlanet Delegated Administrator' )",
		"( 1.2.5 NAME 'opaqueState' DESC 'operational, but a client may write it' USAGE dSAOperation SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.2.6 NAME 'opaqueSubState' SUP opaqueState )",
		"( 1.2.7 NAME 'stamped' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 NO-USER-MODIFICATION )",
	)
)

// schemaDir is a server whose root DSE names a subschema subentry holding defs.
type schemaDir struct{ types, classes []string }

func (schemaDir) Walk(context.Context, string, string, []string, func(directory.Entry) error) error {
	return nil
}
func (s schemaDir) Get(_ context.Context, dnStr string, _ []string) (*directory.Entry, error) {
	switch dnStr {
	case "":
		return &directory.Entry{Attrs: map[string][]string{"subschemaSubentry": {"cn=Subschema"}}}, nil
	case "cn=Subschema":
		return &directory.Entry{DN: dnStr, Attrs: map[string][]string{"attributeTypes": s.types, "objectClasses": s.classes}}, nil
	}
	return nil, nil
}
func (schemaDir) Add(context.Context, directory.Entry, ...directory.Control) error { return nil }
func (schemaDir) Replace(context.Context, string, map[string][]string) error       { return nil }
func (schemaDir) AddValues(context.Context, string, string, []string) error        { return nil }

// What a client can write on a class of a subschema: its MUST and MAY and those of the classes above it, by each
// attribute's first name (an OID named too), without what only the server writes, an operational usage carried down
// to a subtype; an auxiliary class is a class of its own; extensibleObject takes every attribute a client can write;
// a DESC is not read for keywords.
func TestWritableOfASubschema(t *testing.T) {
	ctx := context.Background()
	got, ok, err := subschema{}.Writable(ctx, schemaDir{openLDAPTypes, openLDAPClasses},
		[]string{"inetOrgPerson", "posixAccount", "extensibleObject", "decoy"})
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	has := func(class string) map[string]bool { return Set(got[class]) }
	user := has("inetOrgPerson")
	for _, a := range []string{"objectclass", "sn", "cn", "userpassword", "telephonenumber", "title", "ou", "mail", "uid", "manager", "seealso"} {
		if !user[a] {
			t.Errorf("inetOrgPerson: %s missing from %v", a, got["inetOrgPerson"])
		}
	}
	if user["uidnumber"] || user["surname"] {
		t.Errorf("inetOrgPerson: %v", got["inetOrgPerson"])
	}
	if posix := has("posixAccount"); !posix["uidnumber"] || !posix["loginshell"] || posix["mail"] {
		t.Errorf("posixAccount: %v", got["posixAccount"])
	}
	ext := has("extensibleObject")
	for _, a := range []string{"mail", "uidnumber", "description"} {
		if !ext[a] {
			t.Errorf("extensibleObject: %s missing", a)
		}
	}
	for _, a := range []string{"createtimestamp", "entryuuid", "memberof", "opaquestate", "opaquesubstate", "stamped"} {
		if ext[a] {
			t.Errorf("extensibleObject: %s only the server writes", a)
		}
	}
	if decoy := has("decoy"); !decoy["description"] || decoy["sn"] || decoy["secret"] || len(decoy) != 2 {
		t.Errorf("decoy: %v", got["decoy"])
	}
	if _, _, err := (subschema{}).Writable(ctx, schemaDir{openLDAPTypes, openLDAPClasses}, []string{"nosuchClass"}); err == nil {
		t.Error("a class the schema lacks must be an error")
	}
	if _, ok, err := (subschema{}).Writable(ctx, namingContexts{}, []string{"person"}); ok || err != nil {
		t.Errorf("no subschema: %v %v", ok, err)
	}
}

// The parser keeps a DESC whole and reads list values, bounds and flags.
func TestParseDescriptions(t *testing.T) {
	c, ok := parseObjectClass("( 1.2.3 NAME 'x' DESC 'a ( b $ c ) MUST d' SUP ( p $ q ) AUXILIARY MUST e MAY ( f $ g ) X-ORIGIN ( 'one' 'two' ) )")
	if !ok || c.oid != "1.2.3" || fmt.Sprint(c.sup, c.must, c.may) != "[p q] [e] [f g]" {
		t.Fatalf("%+v %v", c, ok)
	}
	a, ok := parseAttributeType("( 1.2.4 NAME 'y' DESC 'SINGLE-VALUE NO-USER-MODIFICATION' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} )")
	if !ok || a.syntax != "1.3.6.1.4.1.1466.115.121.1.15" || a.single || a.serverOnly {
		t.Fatalf("%+v %v", a, ok)
	}
	a, ok = parseAttributeType("( 1.2.5 NAME 'z' SYNTAX '1.3.6.1.4.1.1466.115.121.1.12' USAGE directoryOperation )")
	if !ok || a.syntax != rfcSyntaxDN || !a.serverOnly {
		t.Fatalf("%+v %v", a, ok)
	}
}

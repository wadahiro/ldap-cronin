package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/dump"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

const (
	gRoot  = "dc=example,dc=org"
	gBase  = "ou=IDM," + gRoot
	gAlice = "uid=alice,ou=People," + gBase
)

// genericSchema is a subschema subentry as OpenLDAP's, cut down to what the entries below hold, and what only the
// server writes.
func genericSchema(d *fakedir.Dir, without ...string) {
	types := []string{
		"( 2.5.4.0 NAME 'objectClass' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		"( 2.5.4.41 NAME 'name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
		"( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )",
		"( 2.5.4.4 NAME ( 'sn' 'surname' ) SUP name )",
		"( 2.5.4.11 NAME ( 'ou' 'organizationalUnitName' ) SUP name )",
		"( 2.5.4.13 NAME 'description' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{1024} )",
		"( 2.5.4.49 NAME 'distinguishedName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		"( 2.5.4.31 NAME 'member' SUP distinguishedName )",
		"( 2.5.4.35 NAME 'userPassword' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
		"( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )",
		"( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'rfc822Mailbox' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} )",
		"( 2.16.840.1.113730.3.1.4 NAME 'employeeType' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.3.6.1.1.1.1.0 NAME 'uidNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
		"( 1.3.6.1.1.1.1.1 NAME 'gidNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
		"( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
		"( 1.3.6.1.4.1.42.2.27.8.1.9 NAME 'shadowLastChange' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
		"( 2.5.18.1 NAME 'createTimestamp' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		"( 2.5.18.2 NAME 'modifyTimestamp' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		"( 2.5.18.3 NAME 'creatorsName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		"( 2.5.18.4 NAME 'modifiersName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		"( 1.3.6.1.1.16.4 NAME 'entryUUID' SYNTAX 1.3.6.1.1.16.1 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		"( 1.2.840.113556.1.2.102 NAME 'memberOf' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 NO-USER-MODIFICATION USAGE dSAOperation )",
	}
	var kept []string
	for _, t := range types {
		drop := false
		for _, w := range without {
			drop = drop || strings.Contains(t, "'"+w+"'")
		}
		if !drop {
			kept = append(kept, t)
		}
	}
	d.Put("", map[string][]string{"subschemaSubentry": {"cn=Subschema"}, "namingContexts": {gRoot}})
	d.Put("cn=Subschema", map[string][]string{"attributeTypes": kept, "objectClasses": {
		"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
		"( 2.5.6.5 NAME 'organizationalUnit' SUP top STRUCTURAL MUST ou MAY description )",
		"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ description ) )",
		"( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL MAY ou )",
		"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( mail $ uid $ employeeType ) )",
		"( 1.3.6.1.1.1.2.0 NAME 'posixAccount' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) MAY userPassword )",
		"( 1.3.6.1.1.1.2.1 NAME 'shadowAccount' SUP top AUXILIARY MUST uid MAY shadowLastChange )",
		"( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL MUST ( member $ cn ) MAY description )",
	}})
}

// openGeneric opens a session of the generic profile from src to dst with more after [scope].
func openGeneric(t *testing.T, src, dst *fakedir.Dir, more string) *Session {
	t.Helper()
	return openGenericConfig(t, src, dst, "[source]\nurl = \"ldaps://src:636\"\nbind_dn = \"cn=a\"\n[target]\nurl = \"ldaps://dst:636\"\nbind_dn = \"cn=a\"\n"+
		"[scope]\nprofile = \"ldap\"\nbase_dn = \""+gBase+"\"\n"+more)
}

// openGenericConfig opens a session of the config text, its source src (or the dump it names) and its target dst.
func openGenericConfig(t *testing.T, src, dst *fakedir.Dir, text string) *Session {
	t.Helper()
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	w := &world{src: src, dst: dst, pool: true}
	s, err := Open(context.Background(), cfg, w.secrets(), w.dial, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// A generic server copies every attribute a client can write by default, as AD does: what the classes its entries
// hold allow, an auxiliary class's included (employeeType of inetOrgPerson, uidNumber of posixAccount, which no
// allow list names), and with [mapping] mode = "preserve" (the default) the source's entryUUID and creation
// metadata, sent once in the Add with the relax control and never as attributes of the lists. An attribute the
// target's schema lacks is left out with a note; diff then finds nothing.
func TestAGenericServerCopiesEveryAttributeAClientCanWrite(t *testing.T) {
	ctx := context.Background()
	src := fakedir.New(gRoot)
	genericSchema(src)
	src.Put(gRoot, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"example"}})
	src.Put(gBase, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}, "description": {"identity"}})
	src.Put("ou=People,"+gBase, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"People"}})
	src.Put(gAlice, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount", "shadowAccount"},
		"cn": {"Alice"}, "sn": {"A"}, "uid": {"alice"}, "mail": {"alice@example.org"}, "employeeType": {"staff"},
		"uidNumber": {"1001"}, "gidNumber": {"1001"}, "homeDirectory": {"/home/alice"}, "shadowLastChange": {"20000"},
		"userPassword": {"{SSHA}real-hash"}, "createTimestamp": {"20200102030405Z"}, "creatorsName": {"cn=admin," + gRoot}})
	src.Put("cn=Eng,"+gBase, map[string][]string{"objectClass": {"top", "groupOfNames"}, "cn": {"Eng"}, "member": {gAlice}})
	dst := fakedir.New(gRoot)
	dst.IDPrefix = 0xd1
	dst.Relax = profile.RelaxOID
	genericSchema(dst, "shadowLastChange")
	dst.Put(gRoot, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"example"}})

	s := openGeneric(t, src, dst, "")
	user, _ := s.Job.Kind(profile.KindUser)
	attrs := profile.Set(user.Attrs)
	for _, a := range []string{"employeetype", "uidnumber", "homedirectory", "shadowlastchange", "mail", "sn"} {
		if !attrs[a] {
			t.Errorf("%s is not copied: %v", a, user.Attrs)
		}
	}
	for _, a := range []string{"entryuuid", "createtimestamp", "creatorsname", "memberof", "userpassword"} {
		if attrs[a] {
			t.Errorf("%s is in the lists: %v", a, user.Attrs)
		}
	}
	if !s.Job.AllWritable {
		t.Fatal("mode = \"all\" is the default")
	}

	var log bytes.Buffer
	if _, err := s.Clone(ctx, false, &log, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if !strings.Contains(log.String(), "shadowLastChange") {
		t.Errorf("no note of the attribute the target lacks:\n%s", log.String())
	}
	got, want := dst.Lookup(gAlice), src.Lookup(gAlice)
	if got == nil {
		t.Fatalf("alice was not cloned:\n%s", log.String())
	}
	for _, a := range []string{"employeeType", "uidNumber", "entryUUID", "createTimestamp", "creatorsName"} {
		if g, w := got.Values(a), want.Values(a); len(g) != 1 || g[0] != w[0] {
			t.Errorf("%s: %v, the source's %v", a, g, w)
		}
	}
	if len(got.Values("shadowLastChange")) != 0 || got.Values("userPassword")[0] == "{SSHA}real-hash" {
		t.Errorf("alice: %v", got.Attrs)
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitSame {
		t.Fatalf("diff: %d %v\n%s", code, err, out.String())
	}
}

// mode = "allowlist" keeps a generic server's allow lists, extra_include adding to them.
func TestAGenericServerKeepsItsListsOnRequest(t *testing.T) {
	src := fakedir.New(gRoot)
	genericSchema(src)
	src.Put(gBase, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}})
	s := openGeneric(t, src, fakedir.New(gRoot), "[attributes]\nmode = \"allowlist\"\nextra_include = [\"employeeType\"]\n")
	user, _ := s.Job.Kind(profile.KindUser)
	if attrs := profile.Set(user.Attrs); s.Job.AllWritable || !attrs["employeetype"] || attrs["shadowlastchange"] {
		t.Fatalf("%v %v", s.Job.AllWritable, user.Attrs)
	}
}

// exclude takes attributes out of every attribute a client can write, as on AD.
func TestAGenericServerExcludesFromEveryAttribute(t *testing.T) {
	src := fakedir.New(gRoot)
	genericSchema(src)
	src.Put(gBase, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}})
	src.Put(gAlice, map[string][]string{"objectClass": {"top", "inetOrgPerson", "posixAccount"}, "cn": {"Alice"}, "sn": {"A"},
		"uid": {"alice"}, "uidNumber": {"1"}, "gidNumber": {"1"}, "homeDirectory": {"/home/alice"}})
	s := openGeneric(t, src, fakedir.New(gRoot), "[attributes]\nexclude = [\"uidNumber\", \"employeeType\"]\n")
	user, _ := s.Job.Kind(profile.KindUser)
	if attrs := profile.Set(user.Attrs); !s.Job.AllWritable || attrs["uidnumber"] || attrs["employeetype"] || !attrs["homedirectory"] {
		t.Fatalf("%v %v", s.Job.AllWritable, user.Attrs)
	}
}

// acmeWorld is a generic source whose naming context is o=acme, which no DC= run names, and a target holding that
// root alone; hidden leaves o=acme out of the source's root DSE, as a server does to an account it shows none.
func acmeWorld(hidden bool) (src, dst *fakedir.Dir) {
	src = fakedir.New("o=acme")
	genericSchema(src)
	root := map[string][]string{"subschemaSubentry": {"cn=Subschema"}}
	if !hidden {
		root["namingContexts"] = []string{"o=acme"}
	}
	src.Put("", root)
	src.Put("o=acme", map[string][]string{"objectClass": {"top", "organization"}, "o": {"acme"}})
	src.Put("ou=People,o=acme", map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"People"}})
	src.Put("uid=erin,ou=People,o=acme", map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson"},
		"cn": {"Erin"}, "sn": {"E"}, "uid": {"erin"}, "mail": {"erin@example.org"}})
	src.Put("cn=Ops,o=acme", map[string][]string{"objectClass": {"top", "groupOfNames"}, "cn": {"Ops"}, "member": {"uid=erin,ou=People,o=acme"}})
	dst = fakedir.New("o=acme")
	dst.IDPrefix = 0xd1
	dst.Relax = profile.RelaxOID
	genericSchema(dst)
	dst.Put("", map[string][]string{"subschemaSubentry": {"cn=Subschema"}, "namingContexts": {"o=acme"}})
	dst.Put("o=acme", map[string][]string{"objectClass": {"top", "organization"}, "o": {"acme"}})
	return src, dst
}

const acmeTarget = "[target]\nurl = \"ldaps://dst:636\"\nbind_dn = \"cn=a\"\n[scope]\nprofile = \"ldap\"\nbase_dn = \"o=acme\"\n"

// A base_dn that is the naming context itself, an o= one that no DC= run names, is its own root: clone takes
// everything under it, dump writes it, and a session from the dump diffs clean.
func TestABaseDNThatIsANamingContextIsItsOwnRoot(t *testing.T) {
	ctx := context.Background()
	src, dst := acmeWorld(false)
	s := openGenericConfig(t, src, dst, "[source]\nurl = \"ldaps://src:636\"\nbind_dn = \"cn=a\"\n"+acmeTarget)
	var log bytes.Buffer
	if _, err := s.Clone(ctx, false, &log, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if dst.Lookup("uid=erin,ou=People,o=acme") == nil || dst.Lookup("cn=Ops,o=acme") == nil {
		t.Fatalf("not cloned:\n%s", log.String())
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitSame {
		t.Fatalf("diff: %d %v\n%s", code, err, out.String())
	}
	path := acmeDump(t, src, "")
	fromDump := openGenericConfig(t, nil, dst, "[source]\nldif = \""+path+"\"\n"+acmeTarget)
	if code, err := fromDump.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitSame {
		t.Fatalf("diff against the dump: %d %v\n%s", code, err, out.String())
	}
}

// A server that names no naming context to the reading account: dump says to give -root-dn, and with it writes a
// dump whose root a session takes without [scope] root_dn.
func TestADumpTakesTheRootItIsGiven(t *testing.T) {
	ctx := context.Background()
	src, dst := acmeWorld(true)
	if _, err := dump.Write(ctx, src, profile.LDAP, dump.Options{BaseDNs: []string{"o=acme"}, Server: "ldaps://src:636"}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "-root-dn") {
		t.Fatalf("without -root-dn: %v", err)
	}
	path := acmeDump(t, src, "o=acme")
	s := openGenericConfig(t, nil, dst, "[source]\nldif = \""+path+"\"\n"+acmeTarget)
	var log bytes.Buffer
	if _, err := s.Clone(ctx, false, &log, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitSame {
		t.Fatalf("diff: %d %v\n%s", code, err, out.String())
	}
}

// acmeDump writes a dump of o=acme of src, with root as its -root-dn, and returns its path.
func acmeDump(t *testing.T, src *fakedir.Dir, root string) string {
	t.Helper()
	var b bytes.Buffer
	if _, err := dump.Write(context.Background(), src, profile.LDAP, dump.Options{BaseDNs: []string{"o=acme"}, RootDN: root, Server: "ldaps://src:636", Version: "test"}, &b); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "acme.ldif")
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

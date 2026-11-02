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

// withClassMay gives the subschema of d an attribute type more, which class's MAY names when named, as a production
// that added its own attributes to a standard class has it.
func withClassMay(d *fakedir.Dir, attr, oid, class string) {
	sub := d.Lookup("cn=Subschema").Attrs
	sub["attributeTypes"] = append(sub["attributeTypes"], "( "+oid+" NAME '"+attr+"' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )")
	if class == "" {
		return
	}
	for i, c := range sub["objectClasses"] {
		if strings.Contains(c, "NAME '"+class+"'") {
			sub["objectClasses"][i] = strings.Replace(c, "MAY ( ", "MAY ( "+attr+" $ ", 1)
		}
	}
}

// The source's inetOrgPerson lets hold an attribute the target's does not, though the target defines it: clone
// leaves it out with a note naming the kind and its classes, instead of every Add of a user holding it being refused,
// and check says so; diff compares the rest.
func TestAnAttributeTheTargetsClassDoesNotAllowIsLeftOut(t *testing.T) {
	ctx := context.Background()
	src, dst := acmeWorld(false)
	withClassMay(src, "acmeLock", "1.3.6.1.4.1.99999.1.20", "inetOrgPerson")
	withClassMay(dst, "acmeLock", "1.3.6.1.4.1.99999.1.20", "")
	src.Lookup("uid=erin,ou=People,o=acme").Attrs["acmeLock"] = []string{"0"}
	s := openGenericConfig(t, src, dst, "[source]\nurl = \"ldaps://src:636\"\nbind_dn = \"cn=a\"\n"+acmeTarget)
	user, _ := s.Job.Kind(profile.KindUser)
	if !profile.Set(user.Attrs)["acmelock"] {
		t.Fatalf("the source's class lets hold it: %v", user.Attrs)
	}
	var report bytes.Buffer
	if _, err := s.Check(ctx, CheckOptions{Config: "c.toml"}, &report); err != nil {
		t.Fatal(err)
	}
	want := "the target's classes of the entries do not allow 1 attributes the source's do"
	if !strings.Contains(report.String(), want) || !strings.Contains(report.String(), "acmeLock (user: top, person, organizationalPerson, inetOrgPerson)") {
		t.Fatalf("check:\n%s", report.String())
	}
	var log bytes.Buffer
	if _, err := s.Clone(ctx, false, &log, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if e := dst.Lookup("uid=erin,ou=People,o=acme"); e == nil || len(e.Values("acmeLock")) != 0 || !strings.Contains(log.String(), want) {
		t.Fatalf("erin: %v\n%s", e, log.String())
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitSame {
		t.Fatalf("diff: %d %v\n%s", code, err, out.String())
	}
}

// policyStore gives d's subschema the classes of a policy store and of an application's entry, and, with entries,
// d an OU holding a store, a rule under it naming a user, and an application entry beside them: entries of no kind.
func policyStore(d *fakedir.Dir, entries bool) {
	sub := d.Lookup("cn=Subschema").Attrs
	sub["attributeTypes"] = append(sub["attributeTypes"],
		"( 1.3.6.1.4.1.99999.1.40 NAME 'acmeStoreId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
		"( 1.3.6.1.4.1.99999.1.41 NAME 'acmeStoreName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.3.6.1.4.1.99999.1.42 NAME 'acmeRuleId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
		"( 1.3.6.1.4.1.99999.1.43 NAME 'acmeRuleText' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.3.6.1.4.1.99999.1.44 NAME 'acmeRuleOwner' SUP distinguishedName )")
	sub["objectClasses"] = append(sub["objectClasses"],
		"( 1.3.6.1.4.1.99999.2.40 NAME 'acmeStore' SUP top STRUCTURAL MUST acmeStoreId MAY acmeStoreName )",
		"( 1.3.6.1.4.1.99999.2.41 NAME 'acmeRule' SUP top STRUCTURAL MUST acmeRuleId MAY ( acmeRuleText $ acmeRuleOwner ) )",
		"( 2.5.6.11 NAME 'applicationProcess' SUP top STRUCTURAL MUST cn MAY description )")
	if !entries {
		return
	}
	d.Put("ou=Policies,o=acme", map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Policies"}})
	d.Put("acmeStoreId=s1,ou=Policies,o=acme", map[string][]string{"objectClass": {"top", "acmeStore"}, "acmeStoreId": {"s1"}, "acmeStoreName": {"Main"}})
	d.Put("acmeRuleId=r1,acmeStoreId=s1,ou=Policies,o=acme", map[string][]string{"objectClass": {"top", "acmeRule"}, "acmeRuleId": {"r1"},
		"acmeRuleText": {"allow /app"}, "acmeRuleOwner": {"uid=erin,ou=People,o=acme"}})
	d.Put("cn=batch,o=acme", map[string][]string{"objectClass": {"top", "applicationProcess"}, "cn": {"batch"}, "description": {"nightly"}})
}

// Entries of no other kind (a policy store's, nested, and an application's) are cloned as they are by the kind that
// takes the rest, with what their classes allow and their references; the root, of no kind either, is left as the
// target has it; diff finds nothing, and a second clone writes nothing.
func TestEntriesOfNoOtherKindAreCloned(t *testing.T) {
	ctx := context.Background()
	src, dst := acmeWorld(false)
	policyStore(src, true)
	policyStore(dst, false)
	src.Lookup("o=acme").Attrs["description"] = []string{"the source's root"}
	s := openGenericConfig(t, src, dst, "[source]\nurl = \"ldaps://src:636\"\nbind_dn = \"cn=a\"\n"+acmeTarget)
	other, ok := s.Job.Kind(profile.KindOther)
	if !ok || !profile.Set(other.Attrs)["acmeruletext"] || !profile.Set(other.Attrs)["acmeruleowner"] {
		t.Fatalf("the rest's kind: %v %+v", ok, other)
	}
	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if len(rep.NotCloned) != 0 {
		t.Fatalf("not cloned: %v\n%s", rep.NotCloned, log.String())
	}
	rule := dst.Lookup("acmeRuleId=r1,acmeStoreId=s1,ou=Policies,o=acme")
	if rule == nil || strings.Join(rule.Values("acmeRuleText"), "") != "allow /app" || strings.Join(rule.Values("acmeRuleOwner"), "") != "uid=erin,ou=People,o=acme" ||
		dst.Lookup("acmeStoreId=s1,ou=Policies,o=acme") == nil || dst.Lookup("cn=batch,o=acme") == nil {
		t.Fatalf("the rule: %v\n%s", rule, log.String())
	}
	for _, op := range dst.Ops {
		if strings.HasSuffix(op, " o=acme") {
			t.Fatalf("the root was written: %s", op)
		}
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitSame {
		t.Fatalf("diff: %d %v\n%s", code, err, out.String())
	}
	log.Reset()
	if rep, err := s.Clone(ctx, false, &log, &log); err != nil || rep.Added+rep.Updated != 0 {
		t.Fatalf("a second clone: %+v %v\n%s", rep, err, log.String())
	}
}

// The kind that takes the rest needs every attribute a client can write: left out of the allow lists by default,
// refused when objects names it; and a user a narrowed filter leaves out is no entry of it.
func TestTheRestKindNeedsModeAllAndKeepsToItsOwn(t *testing.T) {
	src, dst := acmeWorld(false)
	policyStore(src, true)
	policyStore(dst, false)
	src.Lookup("uid=erin,ou=People,o=acme").Attrs["employeeType"] = []string{"staff"}
	// Named by no reference, which would clone it as the user it is.
	src.Put("uid=gus,ou=People,o=acme", map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson"},
		"cn": {"Gus"}, "sn": {"G"}, "uid": {"gus"}, "employeeType": {"contractor"}})
	head := "[source]\nurl = \"ldaps://src:636\"\nbind_dn = \"cn=a\"\n" + acmeTarget
	s := openGenericConfig(t, src, dst, head+"[attributes]\nmode = \"allowlist\"\n")
	if _, ok := s.Job.Kind(profile.KindOther); ok {
		t.Fatal("the allow lists name no attribute of an entry of any class")
	}
	cfg, err := config.Parse([]byte(strings.Replace(head, "base_dn", "objects = [\"ou\", \"other\"]\nbase_dn", 1) + "[attributes]\nmode = \"allowlist\"\n"))
	if err == nil {
		_, err = cfg.JobFor(profile.LDAP)
	}
	if err == nil || !strings.Contains(err.Error(), `mode = "all"`) {
		t.Fatalf("objects naming it with the allow lists: %v", err)
	}

	s = openGenericConfig(t, src, dst, strings.Replace(head, "base_dn", "filters = { user = \"(&(objectClass=inetOrgPerson)(employeeType=staff))\" }\nbase_dn", 1))
	var log bytes.Buffer
	if _, err := s.Clone(context.Background(), false, &log, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if dst.Lookup("uid=gus,ou=People,o=acme") != nil || dst.Lookup("uid=erin,ou=People,o=acme") == nil || dst.Lookup("cn=batch,o=acme") == nil {
		t.Fatalf("gus, left out of the users, is no other entry:\n%s", log.String())
	}
}

// A class of no other kind whose required attribute is a reference: the entry is created with it, as a group that
// needs a member is, instead of stopping the run.
func TestAnOtherEntryThatRequiresAReferenceIsCreatedWithIt(t *testing.T) {
	src, dst := acmeWorld(false)
	policyStore(src, true)
	policyStore(dst, false)
	dst.RequireAttr = map[string]string{"acmerule": "acmeRuleOwner"}
	s := openGenericConfig(t, src, dst, "[source]\nurl = \"ldaps://src:636\"\nbind_dn = \"cn=a\"\n"+acmeTarget)
	var log bytes.Buffer
	if _, err := s.Clone(context.Background(), false, &log, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if e := dst.Lookup("acmeRuleId=r1,acmeStoreId=s1,ou=Policies,o=acme"); e == nil || len(e.Values("acmeRuleOwner")) != 1 {
		t.Fatalf("the rule: %v\n%s", e, log.String())
	}
}

// A secret an entry of no other kind holds (an agent's shared key in a policy store) is masked by a dump's -mask on
// every entry, or on those of no other kind with other:attribute (description: an application entry's, not an OU's);
// the dump holds no value of either, and a clone from the dump writes the mask.
func TestADumpMasksAnAttributeOfOtherEntries(t *testing.T) {
	ctx := context.Background()
	src, dst := acmeWorld(false)
	policyStore(src, true)
	policyStore(dst, false)
	var b bytes.Buffer
	src.Lookup("ou=Policies,o=acme").Attrs["description"] = []string{"the policies"}
	if _, err := dump.Write(ctx, src, profile.LDAP, dump.Options{BaseDNs: []string{"o=acme"}, MaskValue: "********", Masked: []string{"acmeRuleText", "other:description"},
		Server: "ldaps://src:636", Version: "test"}, &b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "allow /app") || !strings.Contains(b.String(), "acmeRuleText: ********") ||
		strings.Contains(b.String(), "nightly") || !strings.Contains(b.String(), "description: the policies") {
		t.Fatalf("the dump:\n%s", b.String())
	}
	path := filepath.Join(t.TempDir(), "masked.ldif")
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	s := openGenericConfig(t, nil, dst, "[source]\nldif = \""+path+"\"\n"+acmeTarget)
	var log bytes.Buffer
	if _, err := s.Clone(ctx, false, &log, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if got := dst.Lookup("acmeRuleId=r1,acmeStoreId=s1,ou=Policies,o=acme").Values("acmeRuleText"); strings.Join(got, "") != "********" {
		t.Fatalf("acmeRuleText: %v\n%s", got, log.String())
	}
	if got := dst.Lookup("cn=batch,o=acme").Values("description"); strings.Join(got, "") != "********" {
		t.Fatalf("the application entry's description: %v", got)
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitSame {
		t.Fatalf("diff against the masked dump: %d %v\n%s", code, err, out.String())
	}
}

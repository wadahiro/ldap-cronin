package ad

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/fakedir"
)

const (
	srcSchemaNC = "CN=Schema,CN=Configuration,DC=prod,DC=example,DC=com"
	dstSchemaNC = "CN=Schema,CN=Configuration,DC=lab,DC=example,DC=com"
)

// schemaDir is a directory with a schema naming context holding the base definitions both sides have.
func schemaDir(nc string) *fakedir.Dir {
	d := fakedir.New(nc)
	d.Put("", map[string][]string{"schemaNamingContext": {nc}})
	attr(d, nc, "cn", "2.5.4.3", map[string][]string{"systemFlags": {"16"}})
	attr(d, nc, "sAMAccountName", "1.2.840.113556.1.4.221", map[string][]string{"systemFlags": {"16"}})
	class(d, nc, "top", "2.5.6.0", map[string][]string{"systemFlags": {"16"}})
	class(d, nc, "user", "1.2.840.113556.1.5.9", map[string][]string{
		"cn": {"User"}, "subClassOf": {"top"}, "systemMayContain": {"sAMAccountName"}, "systemFlags": {"16"},
	})
	class(d, nc, "group", "1.2.840.113556.1.5.8", map[string][]string{
		"cn": {"Group"}, "subClassOf": {"top"}, "systemFlags": {"16"},
	})
	return d
}

func attr(d *fakedir.Dir, nc, name, oid string, more map[string][]string) {
	attrs := map[string][]string{"objectClass": {"top", "attributeSchema"}, "cn": {name}, "lDAPDisplayName": {name},
		"attributeID": {oid}, "attributeSyntax": {"2.5.5.12"}, "oMSyntax": {"64"}, "isSingleValued": {"TRUE"}}
	for k, v := range more {
		attrs[k] = v
	}
	d.Put("CN="+attrs["cn"][0]+","+nc, attrs)
}

func class(d *fakedir.Dir, nc, name, oid string, more map[string][]string) {
	attrs := map[string][]string{"objectClass": {"top", "classSchema"}, "cn": {name}, "lDAPDisplayName": {name},
		"governsID": {oid}, "objectClassCategory": {"1"}}
	for k, v := range more {
		attrs[k] = v
	}
	d.Put("CN="+attrs["cn"][0]+","+nc, attrs)
}

func readBoth(t *testing.T, src, dst *fakedir.Dir) *SchemaPlan {
	t.Helper()
	ctx := context.Background()
	s, err := ReadSchema(ctx, src)
	if err != nil || s == nil {
		t.Fatalf("%v %v", s, err)
	}
	d, err := ReadSchema(ctx, dst)
	if err != nil || d == nil {
		t.Fatalf("%v %v", d, err)
	}
	return PlanSchema(s, d)
}

// The usual extension: an attribute, an auxiliary class allowing it, and that class attached to user. The plan adds
// the attribute, then the class, then extends user, with a reload after each, in the target's naming context.
func TestThePlanCarriesAnExtensionIntoAnotherNamingContext(t *testing.T) {
	src, dst := schemaDir(srcSchemaNC), schemaDir(dstSchemaNC)
	guid := string([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	attr(src, srcSchemaNC, "acmeEmployeeCode", "1.3.6.1.4.1.99999.1.1", map[string][]string{
		"cn": {"acme-Employee-Code"}, "schemaIDGUID": {guid}, "msDS-IntId": {"-1"}, "searchFlags": {"1"},
	})
	class(src, srcSchemaNC, "acmePerson", "1.3.6.1.4.1.99999.2.1", map[string][]string{
		"cn": {"acme-Person"}, "objectClassCategory": {"3"}, "subClassOf": {"top"}, "mayContain": {"acmeEmployeeCode"},
		"defaultObjectCategory": {"CN=acme-Person," + srcSchemaNC}, "systemOnly": {"FALSE"},
	})
	src.Lookup("CN=User," + srcSchemaNC).Attrs["auxiliaryClass"] = []string{"acmePerson"}

	p := readBoth(t, src, dst)
	if strings.Join(p.NewAttributes, ",") != "acmeEmployeeCode" || strings.Join(p.NewClasses, ",") != "acmePerson" ||
		strings.Join(p.Extended, ",") != "user: auxiliaryClass acmePerson" || len(p.Skipped) != 0 {
		t.Fatalf("%+v", p)
	}
	ctx := context.Background()
	if err := p.Apply(ctx, dst, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"add CN=acme-Employee-Code," + dstSchemaNC, "schemaUpdateNow",
		"add CN=acme-Person," + dstSchemaNC, "schemaUpdateNow",
		"addvalues auxiliaryClass CN=User," + dstSchemaNC, "schemaUpdateNow",
	}
	if strings.Join(dst.Ops, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s", strings.Join(dst.Ops, "\n"))
	}
	a := dst.Lookup("CN=acme-Employee-Code," + dstSchemaNC)
	if a.Values("schemaIDGUID")[0] != guid || a.Values("msDS-IntId") != nil || a.Values("searchFlags")[0] != "1" {
		t.Fatalf("the definition must keep what a client sets and nothing the server assigns: %v", a.Attrs)
	}
	c := dst.Lookup("CN=acme-Person," + dstSchemaNC)
	for name, v := range c.Attrs {
		if len(v) == 0 {
			t.Fatalf("a server refuses an attribute without values: %s", name)
		}
	}
	if c.Values("defaultObjectCategory")[0] != "CN=acme-Person,"+dstSchemaNC || c.Values("systemOnly") != nil {
		t.Fatalf("DNs move to the target's naming context: %v", c.Attrs)
	}
	if !readBoth(t, src, dst).Empty() {
		t.Fatal("applied, the plan has nothing left to do")
	}
}

func TestTheLDIFOfAPlan(t *testing.T) {
	src, dst := schemaDir(srcSchemaNC), schemaDir(dstSchemaNC)
	attr(src, srcSchemaNC, "acmeCode", "1.3.6.1.4.1.99999.1.2", map[string][]string{"schemaIDGUID": {"ABCDEFGHIJKLMNOP"}})
	src.Lookup("CN=Group," + srcSchemaNC).Attrs["mayContain"] = []string{"acmeCode"}
	var out bytes.Buffer
	if err := readBoth(t, src, dst).WriteLDIF(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# attributes to add: 1\n#   acmeCode\n",
		"dn: CN=acmeCode," + dstSchemaNC + "\nchangetype: add\nobjectClass: attributeSchema\ncn: acmeCode\n",
		// printable, and still base64: an octet string
		"schemaIDGUID:: QUJDREVGR0hJSktMTU5PUA==\n",
		"dn:\nchangetype: modify\nadd: schemaUpdateNow\nschemaUpdateNow: 1\n-\n",
		"dn: CN=Group," + dstSchemaNC + "\nchangetype: modify\nadd: mayContain\nmayContain: acmeCode\n-\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
}

// What cannot be carried is listed with why, and nothing that depends on it is added.
func TestThePlanLeavesOutWhatItCannotCarry(t *testing.T) {
	src, dst := schemaDir(srcSchemaNC), schemaDir(dstSchemaNC)
	// A newer Windows Server base schema: the target's level is chosen when it is installed.
	attr(src, srcSchemaNC, "msDS-Newer", "1.2.840.113556.1.4.9999", map[string][]string{"systemFlags": {"16"}})
	// The same name, another OID.
	attr(src, srcSchemaNC, "acmeClash", "1.3.6.1.4.1.99999.1.3", nil)
	attr(dst, dstSchemaNC, "acmeClash", "1.3.6.1.4.1.11111.1.3", nil)
	// A class that must contain the base attribute left out, and one deriving from it.
	class(src, srcSchemaNC, "acmeThing", "1.3.6.1.4.1.99999.2.2", map[string][]string{"subClassOf": {"top"}, "mustContain": {"msDS-Newer"}})
	class(src, srcSchemaNC, "acmeSubThing", "1.3.6.1.4.1.99999.2.3", map[string][]string{"subClassOf": {"acmeThing"}})
	// user may contain it on the source.
	src.Lookup("CN=User," + srcSchemaNC).Attrs["systemMayContain"] = []string{"sAMAccountName", "msDS-Newer"}
	// A defunct attribute is no definition at all.
	attr(src, srcSchemaNC, "acmeOld", "1.3.6.1.4.1.99999.1.4", map[string][]string{"isDefunct": {"TRUE"}})

	p := readBoth(t, src, dst)
	if !p.Empty() {
		t.Fatalf("nothing can be carried: %+v", p.Changes)
	}
	got := strings.Join(p.Skipped, "\n")
	for _, want := range []string{
		"attribute msDS-Newer: part of a newer Windows Server base schema",
		"attribute acmeClash: attributeID 1.3.6.1.4.1.99999.1.3 on the source, 1.3.6.1.4.1.11111.1.3 on the target",
		"class acmeThing: mustContain msDS-Newer, which the target lacks",
		"class acmeSubThing: subClassOf acmeThing, which the target lacks",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "acmeOld") || strings.Contains(got, "user: mayContain msDS-Newer") {
		t.Errorf("a defunct definition, or a value naming what is listed already, is not listed:\n%s", got)
	}
}

// New classes come after the new class they derive from, and name each other only once all of them exist.
func TestNewClassesComeInTheOrderTheyDependOnEachOther(t *testing.T) {
	src, dst := schemaDir(srcSchemaNC), schemaDir(dstSchemaNC)
	class(src, srcSchemaNC, "acmeZBase", "1.3.6.1.4.1.99999.2.10", map[string][]string{"subClassOf": {"top"}})
	class(src, srcSchemaNC, "acmeADerived", "1.3.6.1.4.1.99999.2.11", map[string][]string{
		"subClassOf": {"acmeZBase"}, "possSuperiors": {"acmeZBase", "user"}, "systemAuxiliaryClass": {"acmeMixin"},
	})
	class(src, srcSchemaNC, "acmeMixin", "1.3.6.1.4.1.99999.2.12", map[string][]string{"subClassOf": {"top"}, "objectClassCategory": {"3"}})
	p := readBoth(t, src, dst)
	if err := p.Apply(context.Background(), dst, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"add CN=acmeMixin," + dstSchemaNC, "add CN=acmeZBase," + dstSchemaNC, "schemaUpdateNow",
		"add CN=acmeADerived," + dstSchemaNC, "schemaUpdateNow",
		"addvalues auxiliaryClass CN=acmeADerived," + dstSchemaNC, "addvalues possSuperiors CN=acmeADerived," + dstSchemaNC, "schemaUpdateNow",
	}
	if strings.Join(dst.Ops, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s", strings.Join(dst.Ops, "\n"))
	}
	d := dst.Lookup("CN=acmeADerived," + dstSchemaNC)
	if strings.Join(d.Values("possSuperiors"), ",") != "user,acmeZBase" || strings.Join(d.Values("auxiliaryClass"), ",") != "acmeMixin" {
		t.Fatalf("%v", d.Attrs)
	}
}

// What a client can write on a class: through the classes it derives from and their auxiliary classes, without what
// only the server writes, the constructed attributes and the back links (a DN-Binary value is a reference).
func TestWritableAttributesOfAClass(t *testing.T) {
	d := schemaDir(srcSchemaNC)
	for name, more := range map[string]map[string][]string{
		"givenName":       nil,
		"acmeCode":        nil,
		"mixinAttr":       nil,
		"whenChanged":     {"systemOnly": {"TRUE"}},
		"tokenGroups":     {"systemFlags": {"4"}},
		"manager":         {"attributeSyntax": {"2.5.5.1"}, "linkID": {"42"}},
		"directReports":   {"attributeSyntax": {"2.5.5.1"}, "linkID": {"43"}},
		"msExchDelegates": {"attributeSyntax": {"2.5.5.7"}},
	} {
		attr(d, srcSchemaNC, name, "1.3.6.1.4.1.99999.3."+name, more)
	}
	class(d, srcSchemaNC, "person", "2.5.6.6", map[string][]string{"subClassOf": {"top"}, "systemMayContain": {"givenName", "whenChanged"}})
	class(d, srcSchemaNC, "mixin", "1.3.6.1.4.1.99999.4.1", map[string][]string{"subClassOf": {"top"}, "objectClassCategory": {"3"}, "mayContain": {"mixinAttr"}})
	class(d, srcSchemaNC, "acmeAux", "1.3.6.1.4.1.99999.4.2", map[string][]string{"subClassOf": {"top"}, "objectClassCategory": {"3"},
		"mayContain": {"acmeCode"}, "auxiliaryClass": {"mixin"}})
	u := d.Lookup("CN=User," + srcSchemaNC).Attrs
	u["subClassOf"] = []string{"person"}
	u["mayContain"] = []string{"tokenGroups", "manager", "directReports", "msExchDelegates", "notDefined"}
	u["auxiliaryClass"] = []string{"acmeAux"}
	d.Lookup("CN=top," + srcSchemaNC).Attrs["systemMustContain"] = []string{"cn"}
	s, err := ReadSchema(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s.Writable("User")
	if !ok || strings.Join(got, ",") != "acmeCode,cn,givenName,manager,mixinAttr,msExchDelegates,sAMAccountName" {
		t.Fatalf("%v %v", got, ok)
	}
	if _, ok := s.Writable("printer"); ok {
		t.Fatal("a class the schema lacks")
	}
}

// A back link is added after its forward link, whatever their names (Windows refuses it before: Exchange's
// assocRemoteDXA, linkID 123, sorts before its forward link); one whose forward link neither schema has is left out.
func TestThePlanAddsBackLinksAfterTheirForwardLinks(t *testing.T) {
	src, dst := schemaDir(srcSchemaNC), schemaDir(dstSchemaNC)
	dn := map[string][]string{"attributeSyntax": {"2.5.5.1"}, "oMSyntax": {"127"}, "isSingleValued": {"FALSE"}}
	with := func(link string) map[string][]string {
		m := map[string][]string{"linkID": {link}}
		for k, v := range dn {
			m[k] = v
		}
		return m
	}
	attr(src, srcSchemaNC, "aBackLink", "1.3.6.1.4.1.99999.20.1", with("123"))
	attr(src, srcSchemaNC, "zForwardLink", "1.3.6.1.4.1.99999.20.2", with("122"))
	attr(src, srcSchemaNC, "orphanBackLink", "1.3.6.1.4.1.99999.20.3", with("125"))
	p := readBoth(t, src, dst)
	var order []string
	for _, c := range p.Changes {
		if c.Refresh {
			order = append(order, "refresh")
		} else if c.Add != nil {
			order = append(order, c.Add["lDAPDisplayName"][0])
		}
	}
	if got := strings.Join(order, ","); got != "zForwardLink,refresh,aBackLink,refresh" {
		t.Fatalf("order: %s", got)
	}
	if !strings.Contains(strings.Join(p.Skipped, "\n"), "orphanBackLink: a back link (linkID 125)") {
		t.Fatalf("left out: %v", p.Skipped)
	}
}

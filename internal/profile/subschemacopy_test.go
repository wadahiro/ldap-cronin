package profile

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/fakedir"
)

const (
	extCode  = "( 1.3.6.1.4.1.99999.1.1 NAME 'acmeCode' DESC 'MUST ( x ) in a DESC' SUP name )"
	extSub   = "( 1.3.6.1.4.1.99999.1.2 NAME 'acmeSubCode' SUP acmeCode )"
	extLevel = "( 1.3.6.1.4.1.99999.1.3 NAME 'acmeLevel' SYNTAX 1.3.6.1.4.1.99999.9 )"
	extRule  = "( 1.3.6.1.4.1.99999.1.4 NAME 'acmeRuled' EQUALITY acmeMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
	extOp    = "( 1.3.6.1.4.1.99999.1.5 NAME 'acmeStamp' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 NO-USER-MODIFICATION USAGE directoryOperation )"
	extMail  = "( 1.3.6.1.4.1.99999.1.6 NAME 'mail' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
	extNamed = "( acmeOther-oid NAME 'acmeOther' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
	extTag   = "( 1.3.6.1.4.1.99999.2.1 NAME 'acmeTag' SUP top AUXILIARY MAY ( acmeCode $ acmeSubCode ) )"
	extBad   = "( 1.3.6.1.4.1.99999.2.2 NAME 'acmePerson' SUP acmeTag AUXILIARY MAY acmeLevel )"
	extChild = "( 1.3.6.1.4.1.99999.2.3 NAME 'acmeChild' SUP acmePerson AUXILIARY )"
)

var (
	baseTypes = []string{
		"( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		"( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
		"( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )",
		"( 2.5.4.4 NAME ( 'sn' 'surname' ) SUP name )",
		"( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'rfc822Mailbox' ) EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} )",
	}
	baseClasses = []string{
		"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
		"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) )",
	}
)

// subschemaServer is a directory whose subschema subentry holds types and classes, with the syntaxes and matching
// rules the base schema uses, and whose root DSE names configContext when it is not "".
func subschemaServer(types, classes []string, configContext string) *fakedir.Dir {
	d := fakedir.New("cn=config")
	root := map[string][]string{"subschemaSubentry": {"cn=Subschema"}}
	if configContext != "" {
		root["configContext"] = []string{configContext}
	}
	d.Put("", root)
	d.Put("cn=Subschema", map[string][]string{"attributeTypes": types, "objectClasses": classes,
		"ldapSyntaxes": {
			"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )", "( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )",
			"( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )", "( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )",
		},
		"matchingRules": {
			"( 2.5.13.0 NAME 'objectIdentifierMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
			"( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
			"( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		}})
	d.Put("cn=config", map[string][]string{"objectClass": {"olcGlobal"}, "cn": {"config"}})
	d.Put("cn=schema,cn=config", map[string][]string{"objectClass": {"olcSchemaConfig"}, "cn": {"schema"}})
	return d
}

// What a generic target lacks is planned each definition after what it depends on, as the source wrote it; what the
// target could not take is left out with why, and so is what depends on it; a class both have that the source's lets
// hold more is noted, and kept.
func TestASubschemaPlanCarriesWhatTheTargetCanTake(t *testing.T) {
	ctx := context.Background()
	src := subschemaServer(append(append([]string(nil), baseTypes...), extSub, extCode, extLevel, extRule, extOp, extMail, extNamed),
		append(append([]string(nil), baseClasses[0], "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY 1.3.6.1.4.1.99999.1.1 )"),
			extChild, extBad, extTag), "")
	dst := subschemaServer(baseTypes, baseClasses, "cn=config")
	c, ok, err := subschema{}.PlanSchema(ctx, src, dst)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	p := c.(*subschemaPlan)
	if strings.Join(p.attrs, "\n") != extCode+"\n"+extSub || strings.Join(p.classes, "\n") != extTag {
		t.Fatalf("attributes:\n%s\nclasses:\n%s", strings.Join(p.attrs, "\n"), strings.Join(p.classes, "\n"))
	}
	var sum bytes.Buffer
	p.WriteSummary(&sum)
	for _, want := range []string{
		"attributes to add: 2", "  acmeCode", "  acmeSubCode", "classes to add: 1", "  acmeTag",
		"attribute acmeLevel: syntax 1.3.6.1.4.1.99999.9, which the target lacks",
		"attribute acmeRuled: matching rule acmeMatch, which the target lacks",
		"attribute acmeStamp: operational",
		"attribute mail: the target gives the name another definition (0.9.2342.19200300.100.1.3)",
		`attribute acmeOther: its OID "acmeOther-oid" is not numeric`,
		"class person: the source's allows 1.3.6.1.4.1.99999.1.1 besides; the target's is kept",
		"class acmePerson: MAY acmeLevel, which the target lacks and does not get",
		"class acmeChild: SUP acmePerson, which the target lacks and does not get",
	} {
		if !strings.Contains(sum.String(), want) {
			t.Errorf("no %q in:\n%s", want, sum.String())
		}
	}

	// Into cn=config: one new schema entry, which LDIF and Apply write alike.
	var ldif bytes.Buffer
	if err := p.WriteLDIF(&ldif); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ldif.String(), "\ndn: "+p.dn()+"\nchangetype: add\nobjectClass: olcSchemaConfig\ncn: "+p.name()+"\nolcAttributeTypes: "+extCode+"\n") ||
		!strings.HasSuffix(p.dn(), ",cn=schema,cn=config") || !strings.Contains(ldif.String(), "ldapi") {
		t.Fatalf("LDIF:\n%s", ldif.String())
	}
	var log bytes.Buffer
	if err := p.Apply(ctx, dst, &log); err != nil {
		t.Fatal(err)
	}
	if e := dst.Lookup(p.dn()); e == nil || strings.Join(e.Values("olcObjectClasses"), "") != extTag || len(e.Values("olcAttributeTypes")) != 2 {
		t.Fatalf("the schema entry: %+v\n%s", e, log.String())
	}
}

// A target without configContext gets the definitions in its subschema subentry, as RFC 4512 has it; one that has
// them all is told so.
func TestASubschemaPlanModifiesTheSubentryWithoutConfigContext(t *testing.T) {
	ctx := context.Background()
	src := subschemaServer(append(append([]string(nil), baseTypes...), extCode, extSub), append(append([]string(nil), baseClasses...), extTag), "")
	dst := subschemaServer(baseTypes, baseClasses, "")
	c, _, err := subschema{}.PlanSchema(ctx, src, dst)
	if err != nil {
		t.Fatal(err)
	}
	var ldif bytes.Buffer
	_ = c.WriteLDIF(&ldif)
	if !strings.Contains(ldif.String(), "dn: cn=Subschema\nchangetype: modify\nadd: attributeTypes\nattributeTypes: "+extCode+"\nattributeTypes: "+extSub+"\n-\nadd: objectClasses\n") {
		t.Fatalf("LDIF:\n%s", ldif.String())
	}
	if err := c.Apply(ctx, dst, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got := dst.Lookup("cn=Subschema").Values("objectClasses"); got[len(got)-1] != extTag {
		t.Fatalf("objectClasses: %v", got)
	}
	again, _, err := subschema{}.PlanSchema(ctx, src, dst)
	if err != nil || !again.Empty() {
		t.Fatalf("the target has them now: %v %+v", err, again)
	}
}

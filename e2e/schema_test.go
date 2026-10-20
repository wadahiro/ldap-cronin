//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// A source AD with an attribute of its own (a schema extension) that the target lacks: clone refuses to start,
// naming the attribute, and writes nothing.
func TestCloneRefusesAnAttributeTheTargetSchemaLacks(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	name := fmt.Sprintf("acmeProbe%06d", runID)
	ctx := context.Background()
	src, dst := dial(t, srcURL), dial(t, dstURL)
	schema := "CN=Schema,CN=Configuration," + realmDN
	if err := src.Add(ctx, directory.Entry{DN: "CN=" + name + "," + schema, Attrs: map[string][]string{
		"objectClass": {"attributeSchema"}, "cn": {name}, "lDAPDisplayName": {name},
		"attributeID": {fmt.Sprintf("1.3.6.1.4.1.99999.9.%d", runID)}, "attributeSyntax": {"2.5.5.12"}, "oMSyntax": {"64"},
		"isSingleValued": {"TRUE"},
	}}); err != nil {
		t.Fatalf("extend the source schema: %v", err)
	}
	scope := fmt.Sprintf("OU=Schema%06d,%s", runID, realmDN)
	if err := src.Add(ctx, directory.Entry{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("Schema%06d", runID)}}}); err != nil {
		t.Fatal(err)
	}
	job := planOptionsFor(t, scope)
	for i := range job.Kinds {
		job.Kinds[i].Attrs = append(job.Kinds[i].Attrs, name)
	}
	_, err := clone.Run(ctx, src, dst, job, clone.Options{UserPassword: fixedPw, Workers: 2}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "target schema lacks") {
		t.Fatalf("clone must refuse before writing: %v", err)
	}
	if e, err := dst.Get(ctx, scope, []string{"ou"}); err != nil || e != nil {
		t.Fatalf("nothing may be written: %v %v", e, err)
	}
}

// A schema extension of the source (an attribute, an auxiliary class allowing it, attached to user) goes to the
// target with schema -apply; then clone copies the attribute and diff finds nothing.
func TestSchemaCarriesAnExtensionThenCloneCopiesIt(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	attr, aux := fmt.Sprintf("acmeCode%06d", runID), fmt.Sprintf("acmeAux%06d", runID)
	ctx := context.Background()
	src := dial(t, srcURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	schema := "CN=Schema,CN=Configuration," + realmDN
	refresh := func() { must(src.AddValues(ctx, "", "schemaUpdateNow", []string{"1"})) }
	must(src.Add(ctx, directory.Entry{DN: "CN=" + attr + "," + schema, Attrs: map[string][]string{
		"objectClass": {"attributeSchema"}, "cn": {attr}, "lDAPDisplayName": {attr},
		"attributeID": {fmt.Sprintf("1.3.6.1.4.1.99999.10.%d", runID)}, "attributeSyntax": {"2.5.5.12"}, "oMSyntax": {"64"},
		"isSingleValued": {"TRUE"},
	}}))
	refresh()
	must(src.Add(ctx, directory.Entry{DN: "CN=" + aux + "," + schema, Attrs: map[string][]string{
		"objectClass": {"classSchema"}, "cn": {aux}, "lDAPDisplayName": {aux},
		"governsID": {fmt.Sprintf("1.3.6.1.4.1.99999.11.%d", runID)}, "objectClassCategory": {"3"}, "subClassOf": {"top"},
		"mayContain": {attr},
	}}))
	refresh()
	must(src.AddValues(ctx, "CN=User,"+schema, "auxiliaryClass", []string{aux}))
	refresh()

	scope := fmt.Sprintf("OU=Ext%06d,%s", runID, realmDN)
	must(src.Add(ctx, directory.Entry{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("Ext%06d", runID)}}}))
	ann := "CN=Ann," + scope
	must(src.Add(ctx, directory.Entry{DN: ann, Attrs: map[string][]string{"objectClass": {"user"}, "cn": {"Ann"},
		"sAMAccountName": {fmt.Sprintf("x%06dann", runID)}, attr: {"E-1"}}}))

	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n"+
		"[target]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n[scope]\nbase_dn = %q\n[attributes]\nextra_include = [%q]\n",
		srcURL, adminDN, dstURL, adminDN, scope, attr)))
	must(err)
	pw := func() (string, error) { return adminPw, nil }
	s, err := app.Open(ctx, cfg, app.Secrets{SourceBind: pw, TargetBind: pw, UserPassword: func() (string, error) { return fixedPw, nil }}, app.LDAP, &bytes.Buffer{})
	must(err)
	t.Cleanup(s.Close)

	if _, err := s.Clone(ctx, false, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "ldap-cronin schema") {
		t.Fatalf("before the schema, clone refuses and names the command: %v", err)
	}
	var ldif, log bytes.Buffer
	must(s.Schema(ctx, false, &ldif, &log))
	for _, want := range []string{"lDAPDisplayName: " + attr, "lDAPDisplayName: " + aux, "dn: CN=User," + schema + "\nchangetype: modify\nadd: auxiliaryClass\nauxiliaryClass: " + aux} {
		if !strings.Contains(ldif.String(), want) {
			t.Fatalf("missing %q in\n%s", want, ldif.String())
		}
	}
	log.Reset()
	must(s.Schema(ctx, true, &bytes.Buffer{}, &log))
	log.Reset()
	must(s.Schema(ctx, false, &bytes.Buffer{}, &log))
	if strings.Contains(log.String(), attr) || strings.Contains(log.String(), aux) {
		t.Fatalf("applied, nothing of it is left to add:\n%s", log.String())
	}

	if _, err := s.Clone(ctx, false, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	dst := dial(t, dstURL)
	if e, err := dst.Get(ctx, ann, []string{attr}); err != nil || e == nil || strings.Join(e.Values(attr), ",") != "E-1" {
		t.Fatalf("the attribute is copied: %v %v", e, err)
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &out); err != nil || code != app.ExitSame {
		t.Fatalf("%d %v\n%s", code, err, out.String())
	}
}

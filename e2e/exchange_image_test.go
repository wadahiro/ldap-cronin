//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/lab"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
)

// A lab image carrying Exchange's schema files (make image EXCHANGE_ISO=...) writes them to the domain it
// provisions, before Samba starts, so the lab is up with them. The files are made up here in the shape of Exchange's
// (nothing of Exchange's own may be in the repository): CRLF, directives and a root DSE record; a class naming an
// attribute added in the same file, which needs a second round; a class naming itself; a value given as the OID of
// one the class holds by name; a definition of Windows' base schema Samba has; a delete and a replace; and a file
// of another series, which is not read.
func TestALabImageWithExchangesSchemaFilesStartsWithThem(t *testing.T) {
	image := os.Getenv("E2E_LAB_IMAGE")
	if image == "" {
		t.Skip("E2E_LAB_IMAGE is not set (tests/e2e.sh sets it)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	const oid = "1.3.6.1.4.1.99999.90."
	attr := func(cn, name, n string) string {
		return "dn: CN=" + cn + ",<SchemaContainerDN>\r\nchangetype: ntdsSchemaAdd\r\nadminDescription: " + cn + "\r\n" +
			"attributeID: " + oid + n + "\r\nattributeSyntax: 2.5.5.12\r\nisSingleValued: TRUE\r\nlDAPDisplayName: " + name + "\r\n" +
			"oMSyntax: 64\r\nobjectCategory: CN=Attribute-Schema,<SchemaContainerDN>\r\nobjectClass: attributeSchema\r\n\r\n"
	}
	files := map[string]string{
		"PostWindows2003_schema0.ldf": "#!LCID[0409]\r\n" + attr("ms-Acme-Code", "acmeCode", "1") + attr("ms-Acme-Note", "acmeNote", "2") +
			"dn: CN=Account-Expires,<SchemaContainerDN>\r\nchangetype: ntdsSchemaAdd\r\nattributeID: 1.2.840.113556.1.4.159\r\n" +
			"attributeSyntax: 2.5.5.16\r\nisSingleValued: TRUE\r\nlDAPDisplayName: accountExpires\r\noMSyntax: 65\r\nobjectClass: attributeSchema\r\n\r\n" +
			"dn: CN=ms-Acme-Container,<SchemaContainerDN>\r\nchangetype: ntdsSchemaAdd\r\ngovernsID: " + oid + "10\r\n" +
			"lDAPDisplayName: acmeContainer\r\nobjectClass: classSchema\r\nobjectClassCategory: 1\r\nsubClassOf: top\r\n" +
			"possSuperiors: container\r\npossSuperiors: organizationalUnit\r\npossSuperiors: " + oid + "10\r\nmayContain: acmeCode\r\n" +
			"objectCategory: CN=Class-Schema,<SchemaContainerDN>\r\n\r\n" +
			"dn:\r\nchangetype: ntdsSchemaModify\r\nreplace: schemaUpdateNow\r\nschemaUpdateNow: 1\r\n-\r\n\r\n",
		"PostWindows2003_schema1.ldf": "dn: CN=ms-Acme-Container,<SchemaContainerDN>\r\nchangetype: ntdsSchemaModify\r\n" +
			"add: mayContain\r\nmayContain: " + oid + "1\r\nmayContain: acmeNote\r\n-\r\n" +
			"delete: possSuperiors\r\npossSuperiors: organizationalUnit\r\n-\r\n\r\n",
		"SchemaVersion.ldf": "dn: CN=ms-Acme-Code,<SchemaContainerDN>\r\nchangetype: ntdsSchemaModify\r\nreplace: searchFlags\r\nsearchFlags: 1\r\n-\r\n\r\n",
		"schema0.ldf":       "this series is for older forests and is not read\r\n",
	}
	dir := t.TempDir()
	for name, body := range files {
		must(os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
	must(os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM "+image+"\nCOPY *.ldf /exchange/\n"), 0o600))
	tag := fmt.Sprintf("ldap-cronin/samba-ad:e2e-exchange-%d", time.Now().UnixNano()%1_000_000)
	if out, err := exec.Command("docker", "build", "-q", "-t", tag, dir).CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", tag).Run() })

	const realm, password = "exchange-e2e.test", "Adm1n-Passw0rd!"
	base := lab.BaseDN(realm)
	state := t.TempDir()
	var out, errw bytes.Buffer
	l := &lab.Lab{
		D: lab.ExecDocker{}, Out: &out, Err: &errw, Prompt: noPrompt{}, Prefix: fmt.Sprintf("exche2e%d", time.Now().UnixNano()%1_000_000),
		Version: "e2e", Dirs: lab.Dirs{State: state, Snapshots: state + "/snapshots"}, Sleep: time.Sleep, Now: time.Now,
		Getenv: func(string) string { return "" },
	}
	t.Cleanup(func() { _ = l.Reset(context.Background(), lab.ResetOptions{Yes: true, Snapshots: true}) })
	ldaps := freePort(t)
	started := time.Now()
	if err := l.Up(context.Background(), lab.UpOptions{Image: tag, Flags: lab.Settings{Domain: realm, AdminPassword: password, LDAPPort: freePort(t), LDAPSPort: ldaps}}); err != nil {
		t.Fatalf("up: %v\n%s%s", err, out.String(), errw.String())
	}
	t.Logf("up with the schema files: %.1fs", time.Since(started).Seconds())

	ad, err := ldapdir.Dial(ldapdir.ConnConfig{URL: fmt.Sprintf("ldaps://%s:%d", env("E2E_LAB_HOST", "localhost"), ldaps),
		BindDN: "CN=Administrator,CN=Users," + base, Password: password, InsecureSkipVerify: true}, 1)
	must(err)
	defer ad.Close()
	ctx := context.Background()
	schema := "CN=Schema,CN=Configuration," + base
	get := func(dn string, attrs ...string) *directory.Entry {
		t.Helper()
		e, err := ad.Get(ctx, dn, attrs)
		if err != nil || e == nil {
			t.Fatalf("%s: %v %v", dn, e, err)
		}
		return e
	}
	c := get("CN=ms-Acme-Container,"+schema, "mayContain", "possSuperiors")
	if got := strings.ToLower(strings.Join(c.Values("mayContain"), ",")); got != "acmecode,acmenote" && got != "acmenote,acmecode" {
		t.Errorf("the note added, the code given as its OID not twice: %v", c.Values("mayContain"))
	}
	if got := strings.ToLower(strings.Join(c.Values("possSuperiors"), ",")); !strings.Contains(got, "acmecontainer") ||
		!strings.Contains(got, "container") || strings.Contains(got, "organizationalunit") {
		t.Errorf("itself added once the class exists, organizationalUnit deleted: %v", c.Values("possSuperiors"))
	}
	if v := get("CN=ms-Acme-Code,"+schema, "searchFlags").Values("searchFlags"); strings.Join(v, "") != "1" {
		t.Errorf("SchemaVersion.ldf comes last: %v", v)
	}
	must(ad.Add(ctx, directory.Entry{DN: "CN=Gal,CN=Users," + base, Attrs: map[string][]string{
		"objectClass": {"acmeContainer"}, "acmeCode": {"c1"}, "acmeNote": {"n1"}}}))
}

//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/lab"
)

// A config whose [target.lab] names a lab that does not exist: clone creates it like the source, gives its schema
// the source's extension, and clones over LDAP, so the extension's values are copied without a schema step of the
// user's; diff then finds nothing.
func TestCloneCreatesTheLabLikeTheSourceAndGivesItTheSchema(t *testing.T) {
	image := os.Getenv("E2E_LAB_IMAGE")
	if image == "" {
		t.Skip("E2E_LAB_IMAGE is not set (tests/e2e.sh sets it)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	ctx := context.Background()
	runID := time.Now().UnixNano() % 1_000_000
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	// An extension of the source's: an attribute on an auxiliary class of user.
	src := dial(t, srcURL)
	attr, aux := fmt.Sprintf("acmeLab%06d", runID), fmt.Sprintf("acmeLabAux%06d", runID)
	schema := "CN=Schema,CN=Configuration," + realmDN
	refresh := func() { must(src.AddValues(ctx, "", "schemaUpdateNow", []string{"1"})) }
	must(src.Add(ctx, directory.Entry{DN: "CN=" + attr + "," + schema, Attrs: map[string][]string{
		"objectClass": {"attributeSchema"}, "cn": {attr}, "lDAPDisplayName": {attr},
		"attributeID": {fmt.Sprintf("1.3.6.1.4.1.99999.20.%d", runID)}, "attributeSyntax": {"2.5.5.12"}, "oMSyntax": {"64"},
		"isSingleValued": {"TRUE"},
	}}))
	refresh()
	must(src.Add(ctx, directory.Entry{DN: "CN=" + aux + "," + schema, Attrs: map[string][]string{
		"objectClass": {"classSchema"}, "cn": {aux}, "lDAPDisplayName": {aux},
		"governsID": {fmt.Sprintf("1.3.6.1.4.1.99999.21.%d", runID)}, "objectClassCategory": {"3"}, "subClassOf": {"top"},
		"mayContain": {attr},
	}}))
	refresh()
	must(src.AddValues(ctx, "CN=User,"+schema, "auxiliaryClass", []string{aux}))
	refresh()
	scope := fmt.Sprintf("OU=Lab%06d,%s", runID, realmDN)
	ann := "CN=Ann," + scope
	must(src.Add(ctx, directory.Entry{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("Lab%06d", runID)}}}))
	must(src.Add(ctx, directory.Entry{DN: ann, Attrs: map[string][]string{"objectClass": {"user"}, "cn": {"Ann"},
		"sAMAccountName": {fmt.Sprintf("l%06dann", runID)}, attr: {"E-1"}}}))

	var out, errw bytes.Buffer
	ldap, ldaps := freePort(t), freePort(t)
	l := &lab.Lab{
		D: lab.ExecDocker{}, Out: &out, Err: &errw, Prompt: noPrompt{}, Prefix: fmt.Sprintf("labt%d", runID), Version: "e2e",
		Dirs: lab.Dirs{State: t.TempDir(), Snapshots: t.TempDir()}, Sleep: time.Sleep, Now: time.Now,
		Getenv: func(k string) string {
			if k == "AD_LDAP_PORT" {
				return strconv.Itoa(ldap)
			}
			return ""
		},
		FreePort: func() (int, error) { return freePort(t), nil },
	}
	t.Cleanup(func() { _ = l.Reset(context.Background(), lab.ResetOptions{Yes: true, Snapshots: true}) })

	host := env("E2E_LAB_HOST", "localhost")
	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n"+
		"[target]\nurl = \"ldaps://%s:%d\"\nbind_dn = %q\ninsecure_skip_verify = true\n[target.lab]\nprefix = %q\nimage = %q\n"+
		"[scope]\nbase_dn = %q\n[attributes]\nextra_include = [%q]\n",
		srcURL, adminDN, host, ldaps, adminDN, l.Prefix, image, scope, attr)))
	must(err)
	pw := func() (string, error) { return adminPw, nil }
	s, err := app.Open(ctx, cfg, app.Secrets{SourceBind: pw, TargetBind: pw, UserPassword: func() (string, error) { return fixedPw, nil }}, app.LDAP, &bytes.Buffer{})
	must(err)
	t.Cleanup(s.Close)

	var log bytes.Buffer
	rep, err := s.CloneLab(ctx, l, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s\n%s", err, log.String(), errw.String())
	}
	t.Logf("clone:\n%s", log.String())
	if rep.Added == 0 || !strings.Contains(log.String(), "the lab's schema lacks definitions of the source's; adding them:") {
		t.Fatalf("the lab is created, given the schema and cloned into: %+v\n%s", rep, log.String())
	}
	dst := dial(t, fmt.Sprintf("ldaps://%s:%d", host, ldaps))
	if e, err := dst.Get(ctx, ann, []string{attr}); err != nil || e == nil || strings.Join(e.Values(attr), "") != "E-1" {
		t.Fatalf("the extension's value is copied: %v %v", e, err)
	}
	var diffOut bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &diffOut); err != nil || code != app.ExitSame {
		t.Fatalf("%d %v\n%s", code, err, diffOut.String())
	}
	// A second clone finds the lab running and its schema complete, and writes nothing.
	log.Reset()
	if rep, err := s.CloneLab(ctx, l, &log, &log); err != nil || rep.Added != 0 || strings.Contains(log.String(), "adding them") {
		t.Fatalf("a second clone: %+v %v\n%s", rep, err, log.String())
	}
}

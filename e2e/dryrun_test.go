//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// clone -dry-run -with-password writes an LDIF that ldapmodify alone loads into Samba: the user gets the fixed
// password (a modify over LDAPS) and then the source userAccountControl, so it can bind, and diff finds nothing.
func TestDryRunWithThePasswordLoadsWithLdapmodify(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	scope := fmt.Sprintf("OU=Ldif%06d,%s", runID, realmDN)
	ann := "CN=Ann," + scope
	ctx := context.Background()
	src := dial(t, srcURL)
	for _, e := range []directory.Entry{
		{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("Ldif%06d", runID)}}},
		{DN: ann, Attrs: map[string][]string{"objectClass": {"user"}, "cn": {"Ann"}, "sAMAccountName": {fmt.Sprintf("l%06dann", runID)},
			"title": {"Engineer"}}},
		{DN: "CN=Team," + scope, Attrs: map[string][]string{"objectClass": {"group"}, "cn": {"Team"},
			"sAMAccountName": {fmt.Sprintf("l%06dteam", runID)}, "member": {ann}}},
	} {
		if err := src.Add(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	// Enabled, as a user in production is; Samba creates it disabled without a password.
	if err := src.Replace(ctx, ann, map[string][]string{"unicodePwd": {profile.EncodePassword(fixedPw)}}); err != nil {
		t.Fatal(err)
	}
	if err := src.Replace(ctx, ann, map[string][]string{"userAccountControl": {"512"}}); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n"+
		"[target]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n[scope]\nbase_dn = %q\n", srcURL, adminDN, dstURL, adminDN, scope)))
	if err != nil {
		t.Fatal(err)
	}
	pw := func() (string, error) { return adminPw, nil }
	s, err := app.Open(ctx, cfg, app.Secrets{SourceBind: pw, TargetBind: pw, UserPassword: func() (string, error) { return fixedPw, nil }}, app.LDAP, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.WithPassword = true
	var out bytes.Buffer
	if _, err := s.Clone(ctx, true, &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	load := exec.Command("docker", "compose", "-f", "../docker-compose.yml", "exec", "-T", "-e", "LDAPTLS_REQCERT=never", "ad",
		"ldapmodify", "-x", "-H", "ldaps://127.0.0.1", "-D", adminDN, "-w", adminPw)
	load.Stdin = &out
	if got, err := load.CombinedOutput(); err != nil {
		t.Fatalf("ldapmodify: %v\n%s", err, got)
	}

	conn, err := ldap.DialURL(dstURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Bind(ann, fixedPw); err != nil {
		t.Fatalf("Ann binds with the fixed password the LDIF gave her: %v", err)
	}
	if code, err := s.Diff(ctx, app.DiffOutput{}, &bytes.Buffer{}); err != nil || code != app.ExitSame {
		t.Fatalf("the loaded LDIF is what clone gives: %d %v", code, err)
	}
}

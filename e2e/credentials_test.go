//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// [attributes] credentials = "copy" against Samba: the credentials the source returns are copied (here userPKCS12,
// and userPassword if Samba returns it), the fixed password still logs the user on, and diff finds nothing.
func TestCredentialsCopyAgainstSamba(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	ctx := context.Background()
	src, dst := dial(t, srcURL), dial(t, dstURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	scope := fmt.Sprintf("OU=Cred%06d,%s", runID, realmDN)
	ann := "CN=Ann," + scope
	must(src.Add(ctx, directory.Entry{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("Cred%06d", runID)}}}))
	must(src.Add(ctx, directory.Entry{DN: ann, Attrs: map[string][]string{"objectClass": {"user"}, "cn": {"Ann"},
		"sAMAccountName": {fmt.Sprintf("c%06dann", runID)}, "userPKCS12": {"\x30\x82\x01\x0a not a real key"}}}))
	// A password set and the account enabled, so the clone is neither disabled nor a must-change user and can log on.
	must(src.Replace(ctx, ann, map[string][]string{"unicodePwd": {profile.EncodePassword("Src-Passw0rd!")}}))
	must(src.Replace(ctx, ann, map[string][]string{"userAccountControl": {"512"}}))
	// Whether Samba stores and returns a userPassword depends on dSHeuristics (fUserPwdSupport); record what it does.
	if err := src.Replace(ctx, ann, map[string][]string{"userPassword": {"Prod-Secret-1"}}); err != nil {
		t.Logf("the source refuses userPassword: %v", err)
	}
	held, err := src.Get(ctx, ann, []string{"userPKCS12", "userPassword"})
	must(err)
	t.Logf("the source returns: userPKCS12 %d values, userPassword %d values", len(held.Values("userPKCS12")), len(held.Values("userPassword")))
	if len(held.Values("userPKCS12")) != 1 {
		t.Fatalf("the source does not return userPKCS12 to the Administrator: %v", held.Attrs)
	}

	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n"+
		"[target]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n[scope]\nbase_dn = %q\n[attributes]\ncredentials = \"copy\"\n",
		srcURL, adminDN, dstURL, adminDN, scope)))
	must(err)
	pw := func() (string, error) { return adminPw, nil }
	s, err := app.Open(ctx, cfg, app.Secrets{SourceBind: pw, TargetBind: pw, UserPassword: func() (string, error) { return fixedPw, nil }}, app.LDAP, &bytes.Buffer{})
	must(err)
	t.Cleanup(s.Close)
	var log bytes.Buffer
	if _, err := s.Clone(ctx, false, &log, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if strings.Contains(log.String(), "Prod-Secret-1") || strings.Contains(log.String(), "not a real key") {
		t.Fatalf("clone's log prints a credential:\n%s", log.String())
	}
	got, err := dst.Get(ctx, ann, []string{"userPKCS12", "userPassword"})
	must(err)
	for _, a := range []string{"userPKCS12", "userPassword"} {
		if strings.Join(got.Values(a), "|") != strings.Join(held.Values(a), "|") {
			t.Errorf("%s on the target: %d values, the source's: %d", a, len(got.Values(a)), len(held.Values(a)))
		}
	}

	conn, err := ldap.DialURL(dstURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	must(err)
	defer conn.Close()
	if err := conn.Bind(ann, fixedPw); err != nil {
		t.Fatalf("Ann logs on with the fixed password, whatever userPassword holds: %v", err)
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &out); err != nil || code != app.ExitSame {
		t.Fatalf("diff right after the clone: %d %v\n%s", code, err, out.String())
	}
}

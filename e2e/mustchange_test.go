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
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// A user who must change the password at the next logon (pwdLastSet=0) gets the fixed password and pwdLastSet=0 on
// Samba; one who need not gets a pwdLastSet of the clone's time. A re-run writes nothing.
func TestMustChangePasswordOnSamba(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	ctx := context.Background()
	src := dial(t, srcURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	scope := fmt.Sprintf("OU=Pwd%06d,%s", runID, realmDN)
	must(src.Add(ctx, directory.Entry{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}}}))
	mustChange, free := "CN=Must Change,"+scope, "CN=Free,"+scope
	for i, u := range []string{mustChange, free} {
		must(src.Add(ctx, directory.Entry{DN: u, Attrs: map[string][]string{"objectClass": {"user"}, "sAMAccountName": {fmt.Sprintf("p%06d%d", runID, i)}}}))
	}
	must(src.Replace(ctx, free, map[string][]string{"unicodePwd": {profile.EncodePassword(fixedPw)}}))
	must(src.Replace(ctx, mustChange, map[string][]string{"unicodePwd": {profile.EncodePassword(fixedPw)}}))
	must(src.Replace(ctx, mustChange, map[string][]string{"pwdLastSet": {"0"}}))

	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n"+
		"[target]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n[scope]\nbase_dn = %q\n", srcURL, adminDN, dstURL, adminDN, scope)))
	must(err)
	pw := func() (string, error) { return adminPw, nil }
	s, err := app.Open(ctx, cfg, app.Secrets{SourceBind: pw, TargetBind: pw, UserPassword: func() (string, error) { return fixedPw, nil }}, app.LDAP, &bytes.Buffer{})
	must(err)
	t.Cleanup(s.Close)
	if _, err := s.Clone(ctx, false, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	dst := dial(t, dstURL)
	get := func(u string) string {
		e, err := dst.Get(ctx, u, []string{"pwdLastSet"})
		must(err)
		return strings.Join(e.Values("pwdLastSet"), "")
	}
	if got := get(mustChange); got != "0" {
		t.Fatalf("must change: pwdLastSet %q", got)
	}
	if got := get(free); got == "0" || got == "" {
		t.Fatalf("need not change: pwdLastSet %q", got)
	}
	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil || rep.Added+rep.Updated != 0 {
		t.Fatalf("a re-run writes nothing: %+v %v\n%s", rep, err, log.String())
	}
}

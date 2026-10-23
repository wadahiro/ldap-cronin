//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// The Samba lab's password policy is the weakest a domain takes: a one-character password is accepted, logs on, and
// never expires (maxPwdAge "never", as the EC2 lab's userdata sets it).
func TestTheLabTakesAOneCharacterPassword(t *testing.T) {
	ctx := context.Background()
	dst := dial(t, dstURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	root, err := dst.Get(ctx, realmDN, []string{"maxPwdAge", "minPwdLength", "pwdProperties", "pwdHistoryLength"})
	must(err)
	// maxPwdAge is a negative interval; the largest negative value (or 0) is "never".
	if v := root.Values("maxPwdAge"); len(v) != 1 || (v[0] != "-9223372036854775808" && v[0] != "0") {
		t.Errorf("maxPwdAge: %v", v)
	}
	if fmt.Sprint(root.Values("minPwdLength"), root.Values("pwdHistoryLength")) != "[1] [0]" {
		t.Errorf("minPwdLength %v, pwdHistoryLength %v", root.Values("minPwdLength"), root.Values("pwdHistoryLength"))
	}

	runID := time.Now().UnixNano() % 1_000_000
	ou := fmt.Sprintf("OU=Pol%06d,%s", runID, realmDN)
	user := "CN=A," + ou
	must(dst.Add(ctx, directory.Entry{DN: ou, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("Pol%06d", runID)}}}))
	must(dst.Add(ctx, directory.Entry{DN: user, Attrs: map[string][]string{"objectClass": {"user"}, "cn": {"A"}, "sAMAccountName": {fmt.Sprintf("p%06da", runID)}}}))
	must(dst.Replace(ctx, user, map[string][]string{"unicodePwd": {profile.EncodePassword("a")}}))
	must(dst.Replace(ctx, user, map[string][]string{"userAccountControl": {"512"}}))
	conn, err := ldap.DialURL(dstURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	must(err)
	defer conn.Close()
	if err := conn.Bind(user, "a"); err != nil {
		t.Fatalf("the user logs on with the password \"a\": %v", err)
	}
}

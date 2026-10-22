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
)

// A user of the scope is a member of a group of another OU and of a built-in group (Account Operators): clone
// creates the first and gives both the user, diff finds nothing, and a membership removed on the target shows.
func TestGroupsOutsideTheScopeGetTheirMembersOnSamba(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	ctx := context.Background()
	src := dial(t, srcURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	scope := fmt.Sprintf("OU=Held%06d,%s", runID, realmDN)
	other := fmt.Sprintf("OU=Groups%06d,%s", runID, realmDN)
	for _, ou := range []string{scope, other} {
		must(src.Add(ctx, directory.Entry{DN: ou, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}}}))
	}
	user := "CN=Held User," + scope
	must(src.Add(ctx, directory.Entry{DN: user, Attrs: map[string][]string{"objectClass": {"user"}, "sAMAccountName": {fmt.Sprintf("h%06d", runID)}}}))
	group := "CN=Remote Access," + other
	must(src.Add(ctx, directory.Entry{DN: group, Attrs: map[string][]string{"objectClass": {"group"},
		"sAMAccountName": {fmt.Sprintf("h%06dg", runID)}, "member": {user}}}))
	builtin := "CN=Account Operators,CN=Builtin," + realmDN
	must(src.AddValues(ctx, builtin, "member", []string{user}))
	if e, err := src.Get(ctx, user, []string{"*"}); err == nil && e != nil {
		t.Logf("\"*\" returns memberOf: %v", e.Values("memberOf"))
	}

	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n"+
		"[target]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n[scope]\nbase_dn = %q\n", srcURL, adminDN, dstURL, adminDN, scope)))
	must(err)
	pw := func() (string, error) { return adminPw, nil }
	s, err := app.Open(ctx, cfg, app.Secrets{SourceBind: pw, TargetBind: pw, UserPassword: func() (string, error) { return fixedPw, nil }}, app.LDAP, &bytes.Buffer{})
	must(err)
	t.Cleanup(s.Close)

	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if rep.OutsideGroups != 1 || rep.BuiltinGroups != 1 {
		t.Fatalf("outside %d, built-in %d, left %v\n%s", rep.OutsideGroups, rep.BuiltinGroups, rep.Unheld, log.String())
	}
	dst := dial(t, dstURL)
	for _, g := range []string{group, builtin} {
		e, err := dst.Get(ctx, g, []string{"member"})
		must(err)
		if e == nil || !containsDN(e.Values("member"), user) {
			t.Fatalf("%s does not hold the user on the target: %v", g, e)
		}
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &out); err != nil || code != app.ExitSame {
		t.Fatalf("right after the clone (%d, %v):\n%s", code, err, out.String())
	}
	e, err := dst.Get(ctx, builtin, []string{"member"})
	must(err)
	var rest []string
	for _, v := range e.Values("member") {
		if !strings.EqualFold(v, user) {
			rest = append(rest, v)
		}
	}
	if len(rest) == 0 {
		must(dst.Replace(ctx, builtin, map[string][]string{"member": nil}))
	} else {
		must(dst.Replace(ctx, builtin, map[string][]string{"member": rest}))
	}
	out.Reset()
	if code, err := s.Diff(ctx, app.DiffOutput{}, &out); err != nil || code != app.ExitDiff || !strings.Contains(out.String(), "Account Operators") {
		t.Fatalf("a membership removed on the target shows (%d, %v):\n%s", code, err, out.String())
	}
}

func containsDN(values []string, d string) bool {
	for _, v := range values {
		if strings.EqualFold(v, d) {
			return true
		}
	}
	return false
}

//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// Through the session the commands use, with its connections to the real servers: a dry-run of groups whose members
// are outside the scope, more groups than the workers' queue holds, finishes (with one source connection it waited
// for ever in the reference pass); list-attrs names an attribute the entries hold that no allow list copies.
func TestTheCommandsSessionAgainstSamba(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	root := fmt.Sprintf("OU=Sess%06d,%s", runID, realmDN)
	scope, out := "OU=Scope,"+root, "OU=Out,"+root
	ctx := context.Background()
	src := dial(t, srcURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	carl := "CN=Carl," + out
	for _, e := range []directory.Entry{
		{DN: root, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("Sess%06d", runID)}}},
		{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"Scope"}}},
		{DN: out, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"Out"}}},
		{DN: carl, Attrs: map[string][]string{"objectClass": {"user"}, "cn": {"Carl"}, "sAMAccountName": {fmt.Sprintf("s%06dcarl", runID)},
			"extensionAttribute5": {"not in any allow list"}}},
	} {
		must(src.Add(ctx, e))
	}
	for i := range 40 {
		g := fmt.Sprintf("CN=G%02d,%s", i, scope)
		must(src.Add(ctx, directory.Entry{DN: g, Attrs: map[string][]string{"objectClass": {"group"}, "cn": {fmt.Sprintf("G%02d", i)},
			"sAMAccountName": {fmt.Sprintf("s%06dg%02d", runID, i)}, "member": {carl}}}))
	}
	must(src.Add(ctx, directory.Entry{DN: "CN=Ann," + scope, Attrs: map[string][]string{"objectClass": {"user"}, "cn": {"Ann"},
		"sAMAccountName": {fmt.Sprintf("s%06dann", runID)}, "extensionAttribute5": {"x"}}}))

	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n"+
		"[target]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n[scope]\nbase_dn = %q\n", srcURL, adminDN, dstURL, adminDN, scope)))
	must(err)
	pw := func() (string, error) { return adminPw, nil }
	s, err := app.Open(ctx, cfg, app.Secrets{SourceBind: pw, TargetBind: pw, UserPassword: func() (string, error) { return fixedPw, nil }}, app.LDAP, &bytes.Buffer{})
	must(err)
	t.Cleanup(s.Close)

	timed, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var ldif bytes.Buffer
	rep, err := s.Clone(timed, true, &ldif, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("the dry-run must finish: %v", err)
	}
	if rep.Referenced != 1 || !regexp.MustCompile(`(?m)^add: member$`).MatchString(ldif.String()) {
		t.Fatalf("carl is a referenced object and the members are written: %+v", rep)
	}

	var list bytes.Buffer
	must(s.ListAttrs(ctx, true, &list))
	for _, want := range []string{
		`(?m)^\[user\] 1 entries under ` + regexp.QuoteMeta(scope) + `$`,
		`(?m)^  not copied\s+extensionAttribute5\s+1$`, // the target has the Exchange schema too: no note
		`(?m)^  copied\s+sAMAccountName\s+1$`,
		`(?m)^  never\s+objectSid\s+1  managed by the server$`,
		`(?m)^\[group\] 40 entries`,
		`(?m)^  copied\s+member\s+40$`,
	} {
		if !regexp.MustCompile(want).MatchString(list.String()) {
			t.Errorf("missing %s in\n%s", want, list.String())
		}
	}
}

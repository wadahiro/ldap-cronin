//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
)

// A target cloned from a dump that let displayName through is brought to a dump of that dump with displayName
// masked by running clone again: it writes displayName alone, and diff against the new dump finds nothing.
func TestAReCloneFromADumpOfADumpMasksWhatItMasks(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	ctx := context.Background()
	src := dial(t, srcURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	scope := fmt.Sprintf("OU=Redump%06d,%s", runID, realmDN)
	must(src.Add(ctx, directory.Entry{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("Redump%06d", runID)}}}))
	const users = 3
	for i := range users {
		must(src.Add(ctx, directory.Entry{DN: fmt.Sprintf("CN=r%d,%s", i, scope), Attrs: map[string][]string{"objectClass": {"user"},
			"sAMAccountName": {fmt.Sprintf("r%06du%d", runID, i)}, "displayName": {fmt.Sprintf("Display Name %d", i)}, "title": {"Tester"}}}))
	}
	dir := t.TempDir()
	first, second := filepath.Join(dir, "prod.ldif.gz"), filepath.Join(dir, "masked.ldif.gz")
	pw := func() (string, error) { return adminPw, nil }
	_, err := app.Dump(ctx, app.DumpOptions{Conn: ldapdir.ConnConfig{URL: srcURL, BindDN: adminDN, InsecureSkipVerify: true},
		BaseDNs: []string{scope}, Out: first, MaskValue: config.DefaultMaskValue, Version: "e2e"}, pw, &bytes.Buffer{})
	must(err)
	clone := func(path string) (*app.Session, string) {
		t.Helper()
		cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nldif = %q\n[target]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n"+
			"[scope]\nbase_dn = %q\n", path, dstURL, adminDN, scope)))
		must(err)
		s, err := app.Open(ctx, cfg, app.Secrets{TargetBind: pw, UserPassword: func() (string, error) { return fixedPw, nil }}, app.LDAP, &bytes.Buffer{})
		must(err)
		t.Cleanup(s.Close)
		var log bytes.Buffer
		rep, err := s.Clone(ctx, false, &log, &log)
		if err != nil {
			t.Fatalf("%v\n%s", err, log.String())
		}
		var sum bytes.Buffer
		rep.WriteSummary(&sum)
		return s, log.String() + sum.String()
	}
	clone(first)
	dst := dial(t, dstURL)
	read := func() map[string]string {
		got := map[string]string{}
		must(dst.Walk(ctx, scope, "(objectClass=user)", []string{"displayName", "title", "pwdLastSet", "userAccountControl"}, func(e directory.Entry) error {
			got[strings.ToLower(e.DN)] = strings.Join(e.Values("displayName"), "") + "|" + strings.Join(e.Values("title"), "") + "|" +
				strings.Join(e.Values("pwdLastSet"), "") + "|" + strings.Join(e.Values("userAccountControl"), "")
			return nil
		}))
		return got
	}
	before := read()

	_, err = app.Dump(ctx, app.DumpOptions{From: first, Out: second, MaskValue: config.DefaultMaskValue, Masked: []string{"displayName"}, Version: "e2e"},
		func() (string, error) { t.Fatal("a dump of a dump asks for no password"); return "", nil }, &bytes.Buffer{})
	must(err)
	s, log := clone(second)
	if !strings.Contains(log, fmt.Sprintf("added=0 updated=%d ", users)) {
		t.Fatalf("the re-clone updates each user once:\n%s", log)
	}
	after := read()
	if len(after) != users {
		t.Fatalf("users: %v", after)
	}
	for d, a := range after {
		b := before[d]
		_, restA, _ := strings.Cut(a, "|")
		_, restB, _ := strings.Cut(b, "|")
		if !strings.HasPrefix(a, config.DefaultMaskValue+"|") || restA != restB {
			t.Fatalf("%s: before %q, after %q: displayName masked, nothing else changed (the password neither)", d, b, a)
		}
	}
	var diffOut bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &diffOut); err != nil || code != app.ExitSame {
		t.Fatalf("diff against the new dump: %d %v\n%s", code, err, diffOut.String())
	}
}

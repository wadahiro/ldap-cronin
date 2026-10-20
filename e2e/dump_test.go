//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
	"github.com/wadahiro/ldap-cronin/internal/ldifdir"
)

// A dump of the Samba source holds a group of more members than one response gives (Samba, like AD, returns them in
// ranges of 1500), a manager outside the base DN with the OU above it, and no credential; a clone from it writes
// what a clone from the source writes, and diff against it finds nothing.
func TestCloneFromADumpOfTheSource(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	ctx := context.Background()
	src := dial(t, srcURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	scope := fmt.Sprintf("OU=Dump%06d,%s", runID, realmDN)
	out := fmt.Sprintf("OU=DumpOut%06d,%s", runID, realmDN)
	boss := "CN=Boss," + out
	must(src.Add(ctx, directory.Entry{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("Dump%06d", runID)}}}))
	must(src.Add(ctx, directory.Entry{DN: out, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("DumpOut%06d", runID)}}}))
	must(src.Add(ctx, directory.Entry{DN: boss, Attrs: map[string][]string{"objectClass": {"user"}, "sAMAccountName": {fmt.Sprintf("d%06dboss", runID)}}}))
	const members = 1510
	var dns []string
	for i := range members {
		d := fmt.Sprintf("CN=u%04d,%s", i, scope)
		attrs := map[string][]string{"objectClass": {"user"}, "sAMAccountName": {fmt.Sprintf("d%06du%04d", runID, i)}, "mail": {fmt.Sprintf("u%d@example.com", i)}}
		if i == 0 {
			attrs["manager"] = []string{boss}
		}
		must(src.Add(ctx, directory.Entry{DN: d, Attrs: attrs}))
		dns = append(dns, d)
	}
	group := "CN=All," + scope
	must(src.Add(ctx, directory.Entry{DN: group, Attrs: map[string][]string{"objectClass": {"group"}, "sAMAccountName": {fmt.Sprintf("d%06dall", runID)}}}))
	for lo := 0; lo < members; lo += 500 {
		must(src.AddValues(ctx, group, "member", dns[lo:min(lo+500, members)]))
	}

	path := filepath.Join(t.TempDir(), "prod.ldif.gz")
	var log bytes.Buffer
	_, err := app.Dump(ctx, app.DumpOptions{
		Conn:   ldapdir.ConnConfig{URL: srcURL, BindDN: adminDN, InsecureSkipVerify: true},
		BaseDN: scope, Out: path, MaskValue: "********", Masked: []string{"mail"}, Version: "e2e",
	}, func() (string, error) { return adminPw, nil }, &log)
	must(err)
	d, err := ldifdir.Open(path)
	must(err)
	g, err := d.Get(ctx, group, []string{"member"})
	must(err)
	if g == nil || len(g.Values("member")) != members {
		t.Fatalf("every member, past the first range: %d", len(g.Values("member")))
	}
	if e, _ := d.Get(ctx, boss, []string{"*"}); e == nil {
		t.Fatal("the manager outside the base DN is in the dump")
	}
	if e, _ := d.Get(ctx, "CN=u0000,"+scope, []string{"mail", "unicodePwd"}); e == nil || strings.Join(e.Values("mail"), "") != "********" {
		t.Fatalf("mail masked in the dump: %v", e)
	}
	if entries, err := os.ReadDir(filepath.Dir(path)); err != nil || len(entries) != 1 {
		t.Fatalf("only the dump, no temporary file left: %v %v", entries, err)
	}

	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nldif = %q\n[target]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n"+
		"[scope]\nbase_dn = %q\n", path, dstURL, adminDN, scope)))
	must(err)
	pw := func() (string, error) { return adminPw, nil }
	asked := false
	s, err := app.Open(ctx, cfg, app.Secrets{SourceBind: func() (string, error) { asked = true; return "", nil }, TargetBind: pw,
		UserPassword: func() (string, error) { return fixedPw, nil }}, app.LDAP, &bytes.Buffer{})
	must(err)
	t.Cleanup(s.Close)
	if _, err := s.Clone(ctx, false, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if asked {
		t.Fatal("a clone from a dump asks for no source password")
	}
	dst := dial(t, dstURL)
	if e, err := dst.Get(ctx, group, []string{"member"}); err != nil || e == nil || len(e.Values("member")) != members {
		t.Fatalf("the group on the target: %v", err)
	}
	if e, err := dst.Get(ctx, "CN=u0000,"+scope, []string{"manager", "mail"}); err != nil || e == nil ||
		!strings.EqualFold(strings.Join(e.Values("manager"), ""), boss) || strings.Join(e.Values("mail"), "") != "********" {
		t.Fatalf("the manager outside, created; mail as dumped: %v %v", e, err)
	}
	var diffOut bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &diffOut); err != nil || code != app.ExitSame {
		t.Fatalf("diff against the dump: %d %v\n%s", code, err, diffOut.String())
	}
}

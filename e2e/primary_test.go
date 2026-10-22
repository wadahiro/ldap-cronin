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

// A user whose primary group is a group of another OU: on Samba the group is created with its own RID, the user
// gets it as the primary group, and diff finds nothing; a re-run writes nothing.
func TestThePrimaryGroupOnSamba(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	ctx := context.Background()
	src := dial(t, srcURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	scope := fmt.Sprintf("OU=Prim%06d,%s", runID, realmDN)
	other := fmt.Sprintf("OU=PrimGroups%06d,%s", runID, realmDN)
	for _, ou := range []string{scope, other} {
		must(src.Add(ctx, directory.Entry{DN: ou, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}}}))
	}
	user, group := "CN=Contractor,"+scope, "CN=Contractors,"+other
	must(src.Add(ctx, directory.Entry{DN: group, Attrs: map[string][]string{"objectClass": {"group"}, "sAMAccountName": {fmt.Sprintf("pg%06d", runID)}}}))
	must(src.Add(ctx, directory.Entry{DN: user, Attrs: map[string][]string{"objectClass": {"user"}, "sAMAccountName": {fmt.Sprintf("pu%06d", runID)}}}))
	g, err := src.Get(ctx, group, []string{"objectSid"})
	must(err)
	rid, ok := profile.AD.PrimaryGroup.RID(*g)
	if !ok {
		t.Fatal("the group has no RID")
	}
	must(src.AddValues(ctx, group, "member", []string{user}))
	must(src.Replace(ctx, user, map[string][]string{"primaryGroupID": {rid}}))
	if e, _ := src.Get(ctx, group, []string{"member"}); e != nil {
		t.Logf("the source group's member after the primary group is set: %v", e.Values("member"))
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
	if rep.PrimaryGroups != 1 {
		t.Fatalf("%+v\n%s", rep, log.String())
	}
	dst := dial(t, dstURL)
	tg, err := dst.Get(ctx, group, []string{"objectSid", "member"})
	must(err)
	if tg == nil {
		t.Fatal("the group is not on the target")
	}
	trid, _ := profile.AD.PrimaryGroup.RID(*tg)
	u, err := dst.Get(ctx, user, []string{"primaryGroupID"})
	must(err)
	if got := strings.Join(u.Values("primaryGroupID"), ""); got != trid {
		t.Fatalf("primaryGroupID %s, the target's group is %s (source %s)", got, trid, rid)
	}
	t.Logf("the target group's member: %v (source RID %s, target RID %s)", tg.Values("member"), rid, trid)
	var out bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &out); err != nil || code != app.ExitSame {
		t.Fatalf("right after the clone (%d, %v):\n%s", code, err, out.String())
	}
	log.Reset()
	if rep, err := s.Clone(ctx, false, &log, &log); err != nil || rep.Added+rep.Updated+rep.PrimaryGroups != 0 {
		t.Fatalf("a re-run writes nothing: %+v %v\n%s", rep, err, log.String())
	}
}

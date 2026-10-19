//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/identity"
)

// The membership test on real Samba servers: a group whose members are a user of the scope, a user outside it, a
// built-in group and a well-known principal is cloned with every member (the outside user as a referenced object,
// the principal by SID), diff finds nothing, and removing each kind of member on the target shows.
func TestEveryKindOfMemberIsClonedAndItsRemovalShows(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	root := fmt.Sprintf("OU=Mem%06d,%s", runID, realmDN)
	scope, out := "OU=Scope,"+root, "OU=Out,"+root
	group, ann, carl := "CN=G,"+scope, "CN=Ann,"+scope, "CN=Carl,"+out
	ctx := context.Background()
	src, dst := dial(t, srcURL), dial(t, dstURL)
	// A well-known principal the target does not hold yet, so clone has to write it by SID (Samba provisions some).
	fsp := func(sid string) string { return "CN=" + sid + ",CN=ForeignSecurityPrincipals," + realmDN }
	sid := "S-1-5-11"
	for _, c := range []string{"S-1-1-0", "S-1-5-2", "S-1-5-4", "S-1-5-14", "S-1-5-15", "S-1-5-1000", "S-1-5-11"} {
		if e, err := dst.Get(ctx, fsp(c), []string{"objectClass"}); err == nil && e == nil {
			sid = c
			break
		}
	}
	principal := fsp(sid)
	if e, _ := dst.Get(ctx, principal, []string{"objectClass"}); e != nil {
		t.Logf("every candidate foreign security principal exists on the target; %s is referenced by DN", sid)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []directory.Entry{
		{DN: root, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("Mem%06d", runID)}}},
		{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"Scope"}}},
		{DN: out, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"Out"}}},
		{DN: ann, Attrs: map[string][]string{"objectClass": {"user"}, "cn": {"Ann"}, "sAMAccountName": {fmt.Sprintf("m%06dann", runID)}}},
		{DN: carl, Attrs: map[string][]string{"objectClass": {"user"}, "cn": {"Carl"}, "sAMAccountName": {fmt.Sprintf("m%06dcarl", runID)},
			"title": {"outside the scope"}}},
		{DN: group, Attrs: map[string][]string{"objectClass": {"group"}, "cn": {"G"}, "sAMAccountName": {fmt.Sprintf("m%06dg", runID)}}},
	} {
		must(src.Add(ctx, e))
	}
	// The source's DC creates the principal from the SID, as the target's will. Samba refuses <SID=...> when the
	// principal already exists (68), so an existing one is added by DN, as clone does (plan.RefExisting).
	byPrincipal := "<SID=" + sid + ">"
	if e, err := src.Get(ctx, principal, []string{"objectClass"}); err == nil && e != nil {
		byPrincipal = principal
	}
	must(src.AddValues(ctx, group, "member", []string{ann, carl, domainAdm, byPrincipal}))
	// What the DC made of the SID: a foreign security principal, or the object in CN=WellKnown Security Principals
	// of the configuration (Samba does that for Everyone). Either is the value clone must reproduce.
	for _, v := range mustGet(t, src, group, "member").Values("member") {
		if !dn.Equal(v, ann) && !dn.Equal(v, carl) && !dn.Equal(v, domainAdm) {
			principal = v
		}
	}
	if e, _ := dst.Get(ctx, principal, []string{"objectClass"}); e == nil {
		t.Logf("the principal's member value %s is not on the target: clone writes it by SID", principal)
	} else {
		t.Logf("the principal's member value %s is on the target: clone references it by DN", principal)
	}

	m := markerOf(t, src, dst, scope)
	opt := planOptionsFor(t, scope)
	rep, err := clone.Run(ctx, src, dst, opt, clone.Options{UserPassword: fixedPw, Workers: 4, Marker: &m}, &bytes.Buffer{})
	must(err)
	if rep.Referenced != 1 || rep.WarningCount != 0 {
		t.Fatalf("carl must be cloned as a referenced object and nothing skipped: %+v", rep)
	}
	members := mustGet(t, dst, group, "member").Values("member")
	for _, want := range []string{ann, carl, domainAdm, principal} {
		if !slices.ContainsFunc(members, func(v string) bool { return dn.Equal(v, want) }) {
			t.Fatalf("member %s is missing on the target: %v", want, members)
		}
	}
	diffs, err := runDiffWith(opt, src, dst, identity.ByMarker(m))
	must(err)
	if len(diffs) != 0 {
		var b bytes.Buffer
		for _, d := range diffs {
			diff.Format(&b, d, 10)
		}
		t.Fatalf("a fresh clone must have no differences:\n%s", b.String())
	}

	// The program under test keeps only Ann.
	conn, err := ldap.DialURL(dstURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	must(err)
	defer conn.Close()
	must(conn.Bind(adminDN, adminPw))
	mod := ldap.NewModifyRequest(group, nil)
	mod.Replace("member", []string{ann})
	must(conn.Modify(mod))
	diffs, err = runDiffWith(opt, src, dst, identity.ByMarker(m))
	must(err)
	if len(diffs) != 1 || diffs[0].Attr != "member" {
		t.Fatalf("want one member difference: %+v", diffs)
	}
	removed := append(diffs[0].OnlySource, diffs[0].Source...)
	for _, want := range []string{carl, domainAdm, principal} {
		if !slices.ContainsFunc(removed, func(v string) bool { return dn.Equal(v, want) }) {
			t.Errorf("the removal of %s must show: %v", want, removed)
		}
	}
	if len(removed) != 3 || len(diffs[0].OnlyTarget)+len(diffs[0].Target) != 0 {
		t.Fatalf("exactly the three removed members: %v / %v", removed, strings.Join(append(diffs[0].OnlyTarget, diffs[0].Target...), ","))
	}
}

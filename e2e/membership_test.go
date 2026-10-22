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
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// The membership test on real Samba servers: a group whose members are a user, a computer and a contact of the
// scope, a user and a computer outside it, a built-in group and a well-known principal is cloned with every member
// (the outside ones as referenced objects, the principal by SID), diff finds nothing, and removing each kind of
// member on the target shows.
func TestEveryKindOfMemberIsClonedAndItsRemovalShows(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	root := fmt.Sprintf("OU=Mem%06d,%s", runID, realmDN)
	scope, out := "OU=Scope,"+root, "OU=Out,"+root
	group, ann, carl := "CN=G,"+scope, "CN=Ann,"+scope, "CN=Carl,"+out
	pc, pcOut, contact := "CN=PC1,"+scope, "CN=PC2,"+out, "CN=Partner,"+scope
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
	// A joined workstation: a workstation trust account with its host name and SPNs.
	computer := func(d, sam string) directory.Entry {
		return directory.Entry{DN: d, Attrs: map[string][]string{"objectClass": {"computer"}, "cn": {strings.SplitN(d[3:], ",", 2)[0]},
			"sAMAccountName": {sam + "$"}, "userAccountControl": {"4096"}, "dNSHostName": {sam + ".ad.example.com"},
			"servicePrincipalName": {"HOST/" + sam, "HOST/" + sam + ".ad.example.com"}, "operatingSystem": {"Windows 11 Enterprise"}}}
	}
	for _, e := range []directory.Entry{
		{DN: root, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("Mem%06d", runID)}}},
		{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"Scope"}}},
		{DN: out, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"Out"}}},
		{DN: ann, Attrs: map[string][]string{"objectClass": {"user"}, "cn": {"Ann"}, "sAMAccountName": {fmt.Sprintf("m%06dann", runID)}}},
		{DN: carl, Attrs: map[string][]string{"objectClass": {"user"}, "cn": {"Carl"}, "sAMAccountName": {fmt.Sprintf("m%06dcarl", runID)},
			"title": {"outside the scope"}}},
		{DN: group, Attrs: map[string][]string{"objectClass": {"group"}, "cn": {"G"}, "sAMAccountName": {fmt.Sprintf("m%06dg", runID)}}},
		computer(pc, fmt.Sprintf("m%06dpc1", runID)),
		computer(pcOut, fmt.Sprintf("m%06dpc2", runID)),
		{DN: contact, Attrs: map[string][]string{"objectClass": {"contact"}, "cn": {"Partner"}, "sn": {"Partner"},
			"mail": {"partner@other.example"}, "company": {"Other"}}},
		// Of no kind: not cloned, and counted.
		{DN: "CN=Agent," + pc, Attrs: map[string][]string{"objectClass": {"serviceConnectionPoint"}, "cn": {"Agent"},
			"serviceBindingInformation": {"https://pc1.ad.example.com:8443"}}},
	} {
		must(src.Add(ctx, e))
	}
	// The source's DC creates the principal from the SID, as the target's will. Samba refuses <SID=...> when the
	// principal already exists (68), so an existing one is added by DN, as clone does (plan.RefExisting).
	byPrincipal := "<SID=" + sid + ">"
	if e, err := src.Get(ctx, principal, []string{"objectClass"}); err == nil && e != nil {
		byPrincipal = principal
	}
	must(src.AddValues(ctx, group, "member", []string{ann, carl, pc, pcOut, contact, domainAdm, byPrincipal}))
	// What the DC made of the SID: a foreign security principal, or the object in CN=WellKnown Security Principals
	// of the configuration (Samba does that for Everyone). Either is the value clone must reproduce.
	for _, v := range mustGet(t, src, group, "member").Values("member") {
		if !slices.ContainsFunc([]string{ann, carl, pc, pcOut, contact, domainAdm}, func(m string) bool { return dn.Equal(v, m) }) {
			principal = v
		}
	}
	if e, _ := dst.Get(ctx, principal, []string{"objectClass"}); e == nil {
		t.Logf("the principal's member value %s is not on the target: clone writes it by SID", principal)
	} else {
		t.Logf("the principal's member value %s is on the target: clone references it by DN", principal)
	}

	// Windows takes a well-known principal only in a built-in group: on a Windows target the value is skipped with
	// its reason, and diff counts it instead of comparing it (Samba, which made the source, takes it in any group).
	samba, err := profile.IsSamba(ctx, dst)
	must(err)
	written := []string{ann, carl, pc, pcOut, contact, domainAdm, principal}
	warnings := 0
	if !samba {
		written, warnings = written[:len(written)-1], 1
		t.Log("the target is Windows: the well-known principal is skipped")
	}

	m := markerOf(t, src, dst, scope)
	opt := planOptionsFor(t, scope)
	rep, err := clone.Run(ctx, src, dst, opt, clone.Options{UserPassword: fixedPw, Workers: 4, Marker: &m}, &bytes.Buffer{})
	must(err)
	if rep.Referenced != 2 || rep.WarningCount != warnings {
		t.Fatalf("carl and PC2 must be cloned as referenced objects, and %d skipped: %+v", warnings, rep)
	}
	if fmt.Sprint(rep.ReferencedKinds) != "map[computer:1 user:1]" || fmt.Sprint(rep.NotCloned) != "map[serviceConnectionPoint:1]" {
		t.Fatalf("the counts: referenced %v, not cloned %v", rep.ReferencedKinds, rep.NotCloned)
	}
	if e, _ := dst.Get(ctx, "CN=Agent,"+pc, []string{"cn"}); e != nil {
		t.Fatal("the service connection point must not be cloned")
	}
	// The computers are workstation trust accounts on the target too, with a password, and the same flags.
	for _, d := range []string{pc, pcOut} {
		want, got := mustGet(t, src, d, "userAccountControl", "sAMAccountType"), mustGet(t, dst, d, "userAccountControl", "sAMAccountType", "pwdLastSet")
		if got.Values("userAccountControl")[0] != "4096" || got.Values("sAMAccountType")[0] != want.Values("sAMAccountType")[0] || got.Values("pwdLastSet")[0] == "0" {
			t.Fatalf("%s on the target: %v (source %v)", d, got.Attrs, want.Attrs)
		}
	}
	members := mustGet(t, dst, group, "member").Values("member")
	for _, want := range written {
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
	gone := written[1:]
	for _, want := range gone {
		if !slices.ContainsFunc(removed, func(v string) bool { return dn.Equal(v, want) }) {
			t.Errorf("the removal of %s must show: %v", want, removed)
		}
	}
	if len(removed) != len(gone) || len(diffs[0].OnlyTarget)+len(diffs[0].Target) != 0 {
		t.Fatalf("exactly the removed members: %v / %v", removed, strings.Join(append(diffs[0].OnlyTarget, diffs[0].Target...), ","))
	}
}

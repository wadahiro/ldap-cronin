//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/ad"
	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/plan"
)

// aclACE is an access ACE (type 0 allowed, 1 denied) of a trustee in binary.
func aclACE(typ byte, mask uint32, sid []byte) []byte {
	b := []byte{typ, 0, 0, 0}
	b = binary.LittleEndian.AppendUint32(b, mask)
	b = append(b, sid...)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

// aclSD is a self-relative descriptor of owner, group and the ACEs of its DACL, protected from inheritance when
// protected is set.
func aclSD(protected bool, owner, group []byte, aces ...[]byte) string {
	acl := []byte{2, 0, 0, 0, 0, 0, 0, 0}
	for _, a := range aces {
		acl = append(acl, a...)
	}
	binary.LittleEndian.PutUint16(acl[2:], uint16(len(acl)))
	binary.LittleEndian.PutUint16(acl[4:], uint16(len(aces)))
	control := uint16(0x8004)
	if protected {
		control |= 0x1000
	}
	b := make([]byte, 20)
	b[0] = 1
	binary.LittleEndian.PutUint16(b[2:], control)
	binary.LittleEndian.PutUint32(b[4:], 20)
	b = append(b, owner...)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(b)))
	b = append(b, group...)
	binary.LittleEndian.PutUint32(b[16:], uint32(len(b)))
	return string(append(b, acl...))
}

// [attributes] acl = "copy" against Samba, two domains of their own SIDs: the OU's owner (a user of the scope), its
// ACE for a group of the scope and Domain Admins' come out as the target's SIDs, the ACE of a user clone does not
// copy is left out and counted, a "protect from accidental deletion" ACE keeps even the Administrator from deleting
// the object on the target, and diff finds nothing, on the default ACLs of every object cloned as well.
func TestACLCopyAgainstSamba(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	ctx := context.Background()
	src, dst := dial(t, srcURL), dial(t, dstURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	scope := fmt.Sprintf("OU=Acl%06d,%s", runID, realmDN)
	outside := fmt.Sprintf("OU=AclOut%06d,%s", runID, realmDN)
	ann, team, kept, stranger := "CN=Ann,"+scope, "CN=Team,"+scope, "CN=Kept,"+scope, "CN=Stranger,"+outside
	for _, ou := range []string{scope, outside} {
		must(src.Add(ctx, directory.Entry{DN: ou, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}}}))
	}
	for i, u := range []string{ann, kept, stranger} {
		must(src.Add(ctx, directory.Entry{DN: u, Attrs: map[string][]string{"objectClass": {"user"}, "sAMAccountName": {fmt.Sprintf("a%06d%d", runID, i)}}}))
	}
	must(src.Add(ctx, directory.Entry{DN: team, Attrs: map[string][]string{"objectClass": {"group"}, "sAMAccountName": {fmt.Sprintf("a%06dteam", runID)}}}))
	sidOf := func(d directory.Directory, dn string) []byte {
		t.Helper()
		e, err := d.Get(ctx, dn, []string{"objectSid"})
		must(err)
		if e == nil {
			t.Fatalf("%s is missing", dn)
		}
		return []byte(e.Values("objectSid")[0])
	}
	text := func(sid []byte) string { s, _ := ad.SIDText(sid); return s }
	srcDomain, dstDomain := sidOf(src, realmDN), sidOf(dst, realmDN)
	t.Logf("domain SIDs: source %s, target %s", text(srcDomain), text(dstDomain))
	domainRID := func(domain []byte, rid uint32) []byte {
		return binary.LittleEndian.AppendUint32(append([]byte{1, domain[1] + 1}, domain[2:]...), rid)
	}
	everyone := []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	// A deny ACE first, as ACLs are evaluated in order.
	must(src.Replace(ctx, scope, map[string][]string{"nTSecurityDescriptor": {aclSD(false, sidOf(src, ann), domainRID(srcDomain, 512),
		aclACE(1, 0x10042, everyone), aclACE(0, 0xf01ff, sidOf(src, team)), aclACE(0, 0xf01ff, domainRID(srcDomain, 512)),
		aclACE(0, 0x20094, sidOf(src, stranger)))}}))
	// Protected from accidental deletion, as ADUC sets it: Everyone is denied the object's deletion (and, above, the
	// OU's deletion of a child), keeping the rest.
	cur, err := src.Get(ctx, kept, []string{"nTSecurityDescriptor"})
	must(err)
	protected, _, err := ad.ExplicitOnly([]byte(cur.Values("nTSecurityDescriptor")[0]), nil, func(s string) (string, error) { return s, nil })
	must(err)
	must(src.Replace(ctx, kept, map[string][]string{"nTSecurityDescriptor": {string(protectFromDeletion(t, protected))}}))

	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n"+
		"[target]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n[scope]\nbase_dn = %q\n[attributes]\nacl = \"copy\"\n",
		srcURL, adminDN, dstURL, adminDN, scope)))
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
	if rep.ACEsLeftOut[plan.WhyNoTargetPrincipal] != 1 || !strings.Contains(log.String(), text(sidOf(src, stranger))) {
		t.Fatalf("the stranger's ACE: %+v\n%s", rep.ACEsLeftOut, log.String())
	}
	got, err := dst.Get(ctx, scope, []string{"nTSecurityDescriptor"})
	must(err)
	explicit, err := ad.ExplicitSD([]byte(got.Values("nTSecurityDescriptor")[0]))
	must(err)
	da := text(domainRID(dstDomain, 512))
	want := fmt.Sprintf("O:%s G:%s (1;0x00;0x10042;S-1-1-0) (0;0x00;0xf01ff;%s) (0;0x00;0xf01ff;%s)", text(sidOf(dst, ann)), da, text(sidOf(dst, team)), da)
	if explicit != want {
		t.Fatalf("the target's ACL of the OU:\ngot  %s\nwant %s", explicit, want)
	}

	conn, err := ldap.DialURL(dstURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	must(err)
	defer conn.Close()
	must(conn.Bind(adminDN, adminPw))
	if err := conn.Del(ldap.NewDelRequest(kept, nil)); !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		e, _ := dst.Get(ctx, kept, []string{"nTSecurityDescriptor"})
		acl := ""
		if e != nil {
			acl, _ = ad.ExplicitSD([]byte(e.Values("nTSecurityDescriptor")[0]))
		}
		t.Fatalf("deleting the protected user on the target: %v (its ACL: %s)", err, acl)
	}

	var out bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &out); err != nil || code != app.ExitSame || !strings.Contains(out.String(), "ACLs compared") {
		t.Fatalf("diff right after the clone: %d %v\n%s", code, err, out.String())
	}
	log.Reset()
	if rep, err := s.Clone(ctx, false, &log, &log); err != nil || rep.ACLs != 0 {
		t.Fatalf("a second clone writes no ACL: %v %+v\n%s", err, rep, log.String())
	}
}

// protectFromDeletion adds to an explicit-only descriptor the ACE "Protect object from accidental deletion" sets:
// Everyone denied DELETE and DELETE_TREE (0x10040), first, as a deny ACE goes.
func protectFromDeletion(t *testing.T, raw []byte) []byte {
	t.Helper()
	dacl := int(binary.LittleEndian.Uint32(raw[16:]))
	deny := aclACE(1, 0x10040, []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0})
	out := append(append(append([]byte(nil), raw[:dacl+8]...), deny...), raw[dacl+8:]...)
	binary.LittleEndian.PutUint16(out[dacl+2:], binary.LittleEndian.Uint16(raw[dacl+2:])+uint16(len(deny)))
	binary.LittleEndian.PutUint16(out[dacl+4:], binary.LittleEndian.Uint16(raw[dacl+4:])+1)
	return out
}

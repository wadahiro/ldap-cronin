package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/ad"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/dump"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// testSD builds a self-relative descriptor of owner, group (SID texts) and the ACEs of its DACL.
func testSD(control uint16, owner, group string, aces ...[]byte) string {
	acl := []byte{2, 0, 0, 0, 0, 0, 0, 0}
	for _, a := range aces {
		acl = append(acl, a...)
	}
	binary.LittleEndian.PutUint16(acl[2:], uint16(len(acl)))
	binary.LittleEndian.PutUint16(acl[4:], uint16(len(aces)))
	b := make([]byte, 20)
	b[0] = 1
	binary.LittleEndian.PutUint16(b[2:], control|0x8004)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	b = append(b, fakedir.SID(owner)...)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(b)))
	b = append(b, fakedir.SID(group)...)
	binary.LittleEndian.PutUint32(b[16:], uint32(len(b)))
	return string(append(b, acl...))
}

// testACE is an access ACE (type 0 allowed, 1 denied) of trustee.
func testACE(typ, flags byte, mask uint32, trustee string) []byte {
	b := []byte{typ, flags, 0, 0}
	b = binary.LittleEndian.AppendUint32(b, mask)
	b = append(b, fakedir.SID(trustee)...)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

const (
	srcDomainSID = "S-1-5-21-1-2-3"
	dstDomainSID = "S-1-5-21-7-8-9"
)

// aclWorld is a source of two domains of their own SIDs whose OU=Users is owned by Alice and grants a group of the
// scope full control, denies Everyone its deletion ("protect from accidental deletion"), and names a deleted
// principal's SID.
func aclWorld() (*world, string) {
	w := newWorld()
	team := "CN=Team,OU=Users," + base
	users := "OU=Users," + base
	w.src.Put(domain, map[string][]string{"objectClass": {"domainDNS"}, "objectSid": {fakedir.SID(srcDomainSID)}, "objectGUID": {"0123456789abcdef"}})
	w.dst.Put(domain, map[string][]string{"objectClass": {"domainDNS"}, "objectSid": {fakedir.SID(dstDomainSID)}, "objectGUID": {"fedcba9876543210"}})
	w.dst.SIDs = "7-8-9"
	w.src.Lookup(alice).Attrs["objectSid"] = []string{fakedir.SID(srcDomainSID + "-1105")}
	w.src.Put(team, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Team"}, "sAMAccountName": {"team"},
		"objectSid": {fakedir.SID(srcDomainSID + "-1106")}})
	w.src.Lookup(users).Attrs["nTSecurityDescriptor"] = []string{testSD(0x1000, srcDomainSID+"-1105", srcDomainSID+"-512",
		testACE(0, 0x00, 0xf01ff, srcDomainSID+"-1106"),
		testACE(1, 0x00, 0x10040, "S-1-1-0"),
		testACE(0, 0x00, 0x20094, srcDomainSID+"-1199"),
		testACE(0, 0x12, 0x20094, srcDomainSID+"-513"),
	)}
	return w, users
}

// [attributes] acl = "copy" gives an object the source's owner, group and explicit ACEs with each SID the target's
// object's at the same DN (a built-in one by its RID), leaves out the ACE of a SID no object of the source has, and
// diff compares the result, counting that ACE as not compared.
func TestACLCopyTranslatesTheSIDs(t *testing.T) {
	ctx := context.Background()
	w, users := aclWorld()
	s := w.openWith(t, "[mapping]\nmode = \"off\"\n[attributes]\nacl = \"copy\"\n")
	if s.Job.ACL != plan.ACLTranslated {
		t.Fatalf("job ACL: %q", s.Job.ACL)
	}
	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	sidOf := func(dn string) string {
		sid, _ := ad.SIDText([]byte(w.dst.Lookup(dn).Values("objectSid")[0]))
		return sid
	}
	got, err := ad.ExplicitSD([]byte(w.dst.Lookup(users).Values("nTSecurityDescriptor")[0]))
	if err != nil {
		t.Fatal(err)
	}
	want := "O:" + sidOf(alice) + " G:" + dstDomainSID + "-512 protected (0;0x00;0xf01ff;" + sidOf("CN=Team,"+users) + ") (1;0x00;0x10040;S-1-1-0)"
	if got != want {
		t.Fatalf("the target's ACL:\ngot  %s\nwant %s\n%s", got, want, log.String())
	}
	if rep.ACLs != 1 || rep.ACEsLeftOut[plan.WhyNoSourcePrincipal] != 1 || !strings.Contains(log.String(), srcDomainSID+"-1199") {
		t.Fatalf("%+v\n%s", rep, log.String())
	}
	var sum bytes.Buffer
	rep.WriteSummary(&sum)
	if !strings.Contains(sum.String(), "objects given the source's ACL") || !strings.Contains(sum.String(), "ACEs left out of the ACLs") {
		t.Fatalf("summary:\n%s", sum.String())
	}

	var out bytes.Buffer
	code, err := s.Diff(ctx, DiffOutput{}, &out)
	if err != nil || code != ExitSame || !strings.Contains(out.String(), "ACEs not compared") {
		t.Fatalf("diff right after the clone (%d, %v):\n%s", code, err, out.String())
	}

	// The program under test lifts the protection: diff names the ACE, and clone gives it back once.
	w.dst.Lookup(users).Attrs["nTSecurityDescriptor"] = []string{testSD(0x1000, sidOf(alice), dstDomainSID+"-512",
		testACE(0, 0x00, 0xf01ff, sidOf("CN=Team,"+users)))}
	out.Reset()
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitDiff || !strings.Contains(out.String(), "- 1;0x00;0x10040;S-1-1-0") {
		t.Fatalf("diff after the change (%d, %v):\n%s", code, err, out.String())
	}
	for i, wantACLs := range []int{1, 0} {
		log.Reset()
		rep, err := s.Clone(ctx, false, &log, &log)
		if err != nil || rep.ACLs != wantACLs {
			t.Fatalf("clone %d: %v, ACLs written %d\n%s", i+2, err, rep.ACLs, log.String())
		}
	}
}

// A dry-run cannot read the target's SIDs: its LDIF gives the source's ACL with the source's, and says so.
func TestACLCopyInADryRun(t *testing.T) {
	w, users := aclWorld()
	s := w.openWith(t, "[mapping]\nmode = \"off\"\n[attributes]\nacl = \"copy\"\n")
	var ldif, log bytes.Buffer
	if _, err := s.Clone(context.Background(), true, &ldif, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if !strings.Contains(ldif.String(), "dn: "+users+"\nchangetype: modify\nreplace: nTSecurityDescriptor") ||
		!strings.Contains(log.String(), "a dry-run cannot read the target's") {
		t.Fatalf("LDIF:\n%s\nlog:\n%s", ldif.String(), log.String())
	}
}

// From a dump (which carries the descriptors and objectSid), the trustees are found in it as on the server.
func TestACLCopyFromADump(t *testing.T) {
	ctx := context.Background()
	w, users := aclWorld()
	w.src.Lookup(alice).Attrs["objectCategory"] = []string{"CN=Person," + schemaNC}
	var out bytes.Buffer
	if _, err := dump.Write(ctx, w.src, profile.AD, dump.Options{BaseDNs: []string{base}, Server: "ldaps://src:636", Version: "test"}, &out); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "d.ldif")
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte("[source]\nldif = \"" + path + "\"\n[target]\nurl = \"ldaps://dst:636\"\nbind_dn = \"CN=a\"\n" +
		"[scope]\nprofile = \"ad\"\nbase_dn = \"" + base + "\"\n[mapping]\nmode = \"off\"\n[attributes]\nacl = \"copy\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, cfg, w.secrets(), w.dial, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	sidOf := func(dn string) string {
		sid, _ := ad.SIDText([]byte(w.dst.Lookup(dn).Values("objectSid")[0]))
		return sid
	}
	got, _ := ad.ExplicitSD([]byte(w.dst.Lookup(users).Values("nTSecurityDescriptor")[0]))
	want := "O:" + sidOf(alice) + " G:" + dstDomainSID + "-512 protected (0;0x00;0xf01ff;" + sidOf("CN=Team,"+users) + ") (1;0x00;0x10040;S-1-1-0)"
	if got != want || rep.ACEsLeftOut[plan.WhyNoSourcePrincipal] != 1 {
		t.Fatalf("from the dump:\ngot  %s\nwant %s\n%+v\n%s", got, want, rep.ACEsLeftOut, log.String())
	}
}

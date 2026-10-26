//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// Replication-conflict leftovers against Samba: a user AD renamed to "<name>\nCNF:<GUID>" and "$DUPLICATE-<n>", and
// a computer whose sAMAccountName alone was renamed, both keeping the real object's userPrincipalName and
// servicePrincipalName as AD keeps them. Samba refuses those values on a second object even to the system, so the
// source is given them by writing its database file around samldb, as replication would have left them. clone
// creates the leftovers with their own names and without the shared values (the real objects keep them), a second
// clone writes nothing, and diff finds nothing.
func TestConflictLeftoversAgainstSamba(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	ctx := context.Background()
	src, dst := dial(t, srcURL), dial(t, dstURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	realm := strings.ToLower(strings.NewReplacer("DC=", "", ",", ".").Replace(realmDN))
	scope := fmt.Sprintf("OU=Cnf%06d,%s", runID, realmDN)
	kim, kimLeft := "CN=Kim,"+scope, "CN=Kim\\0ACNF:0f0e0d0c-0b0a-0908-0706-050403020100,"+scope
	pc, pcLeft := "CN=PC9,"+scope, "CN=PC9-old,"+scope
	upn := fmt.Sprintf("n%06dkim@%s", runID, realm)
	spn, oldSPN := fmt.Sprintf("HTTP/n%06dkim.%s", runID, realm), fmt.Sprintf("HTTP/n%06dold.%s", runID, realm)
	host := fmt.Sprintf("HOST/n%06dpc9.%s", runID, realm)
	must(src.Add(ctx, directory.Entry{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("Cnf%06d", runID)}}}))
	must(src.Add(ctx, directory.Entry{DN: kim, Attrs: map[string][]string{"objectClass": {"user"}, "sAMAccountName": {fmt.Sprintf("n%06dkim", runID)},
		"userPrincipalName": {upn}, "servicePrincipalName": {spn}}}))
	must(src.Add(ctx, directory.Entry{DN: kimLeft, Attrs: map[string][]string{"objectClass": {"user"},
		"sAMAccountName": {fmt.Sprintf("$DUPLICATE-%x", runID)}, "servicePrincipalName": {oldSPN}}}))
	must(src.Add(ctx, directory.Entry{DN: pc, Attrs: map[string][]string{"objectClass": {"computer"}, "userAccountControl": {"4096"},
		"sAMAccountName": {fmt.Sprintf("n%06dpc9$", runID)}, "servicePrincipalName": {host}}}))
	must(src.Add(ctx, directory.Entry{DN: pcLeft, Attrs: map[string][]string{"objectClass": {"computer"}, "userAccountControl": {"4096"},
		"sAMAccountName": {fmt.Sprintf("$DUPLICATE-%x", runID+1)}}}))
	// The shared values, written to the domain partition's file without the modules (samldb refuses them): the
	// replication metadata stays without them, which only dbcheck notices.
	raw := "import ldb\nfrom samba.samdb import SamDB\nfrom samba.auth import system_session\nfrom samba.param import LoadParm\n" +
		"lp = LoadParm(); lp.load('/etc/samba/smb.conf')\n" +
		"db = SamDB(url='/var/lib/samba/private/sam.ldb', session_info=system_session(), lp=lp)\n" + rawDomainPartition +
		"for dn, attr, values in ((" + pyStr(kimLeft) + ", 'userPrincipalName', [" + pyStr(upn) + "]), (" + pyStr(kimLeft) + ", 'servicePrincipalName', [" + pyStr(spn) + ", " + pyStr(oldSPN) + "]), (" + pyStr(pcLeft) + ", 'servicePrincipalName', [" + pyStr(host) + "])):\n" +
		"    m = ldb.Message(ldb.Dn(raw, dn))\n" +
		"    m[attr] = ldb.MessageElement(values, ldb.FLAG_MOD_REPLACE, attr)\n" +
		"    raw.modify(m)\n"
	if out, err := exec.Command("docker", "exec", env("E2E_SRC_CONTAINER", "ldap-cronin-ad-src-1"), "python3", "-c", raw).CombinedOutput(); err != nil {
		t.Fatalf("the leftovers' shared values on the source: %v\n%s", err, out)
	}
	if e, err := src.Get(ctx, kimLeft, []string{"userPrincipalName"}); err != nil || e == nil || len(e.Values("userPrincipalName")) != 1 {
		t.Fatalf("the source does not return the leftover's userPrincipalName: %v %+v", err, e)
	}

	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n"+
		"[target]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n[scope]\nbase_dn = %q\n",
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
	if rep.Withheld["userPrincipalName"] != 1 || rep.Withheld["servicePrincipalName"] != 2 {
		t.Fatalf("withheld %+v\n%s", rep.Withheld, log.String())
	}
	attrs := []string{"sAMAccountName", "userPrincipalName", "servicePrincipalName"}
	for dn, want := range map[string]string{
		kim:     fmt.Sprintf("n%06dkim %s %s", runID, upn, spn),
		kimLeft: fmt.Sprintf("$DUPLICATE-%x  %s", runID, oldSPN),
		pc:      fmt.Sprintf("n%06dpc9$  %s", runID, host),
		pcLeft:  fmt.Sprintf("$DUPLICATE-%x  ", runID+1),
	} {
		e, err := dst.Get(ctx, dn, attrs)
		must(err)
		if e == nil {
			t.Fatalf("%s is not on the target", dn)
		}
		var got []string
		for _, a := range attrs {
			got = append(got, strings.Join(e.Values(a), ","))
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%s on the target: %q, want %q", dn, strings.Join(got, " "), want)
		}
	}

	log.Reset()
	if rep, err := s.Clone(ctx, false, &log, &log); err != nil || rep.Added+rep.Updated != 0 {
		t.Fatalf("a second clone writes nothing: %v %+v\n%s", err, rep, log.String())
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &out); err != nil || code != app.ExitSame {
		t.Fatalf("diff: %d %v\n%s", code, err, out.String())
	}
}

// rawDomainPartition is Python that opens, as raw, the database file of the domain partition of the SamDB db
// without Samba's modules (so samldb checks nothing). The file is named in sam.ldb's @PARTITION record: a realm
// with a hyphen has it URL-encoded.
const rawDomainPartition = "_parts = [str(p).split(':', 1) for p in ldb.Ldb('/var/lib/samba/private/sam.ldb', options=['modules:'])" +
	".search('@PARTITION', scope=ldb.SCOPE_BASE, attrs=['partition'])[0]['partition']]\n" +
	"raw = ldb.Ldb('/var/lib/samba/private/' + [f for d, f in _parts if d == str(db.get_default_basedn()).upper()][0], options=['modules:'])\n"

// pyStr quotes s as a Python string literal (the DNs hold a backslash).
func pyStr(s string) string { return "r'" + s + "'" }

//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dump"
	"github.com/wadahiro/ldap-cronin/internal/profile"
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

// A Windows source can hold siblings whose names differ in consecutive spaces only, which Samba takes as one name.
// From such a dump (a Samba source's, given the second sibling by hand), clone adds the first and leaves the second
// out instead of overwriting the first with it, leaving out the member naming it; diff reports NAME_TAKEN.
func TestNamesSambaTakesAsTheSameAreNotOverwritten(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	ctx := context.Background()
	src, dst := dial(t, srcURL), dial(t, dstURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	scope := fmt.Sprintf("OU=Spaces%06d,%s", runID, realmDN)
	one, two := "CN=Lee Ann,"+scope, "CN=Lee  Ann,"+scope
	team := "CN=Team," + scope
	must(src.Add(ctx, directory.Entry{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}}}))
	must(src.Add(ctx, directory.Entry{DN: one, Attrs: map[string][]string{"objectClass": {"user"}, "sAMAccountName": {fmt.Sprintf("s%06da", runID)}}}))
	must(src.Add(ctx, directory.Entry{DN: team, Attrs: map[string][]string{"objectClass": {"group"}, "sAMAccountName": {fmt.Sprintf("s%06dt", runID)}, "member": {one}}}))

	var out bytes.Buffer
	_, err := dump.Write(ctx, src, profile.AD, dump.Options{BaseDNs: []string{scope}, Server: srcURL, Version: "e2e"}, &out)
	must(err)
	// The second sibling: the first's record under the other name, with an objectGUID and sAMAccountName of its own.
	text := out.String()
	start := strings.Index(text, "dn: "+one+"\n")
	if start < 0 {
		t.Fatalf("the dump lacks %s", one)
	}
	end := start + strings.Index(text[start:], "\n\n") + 2
	var sibling []string
	for _, line := range strings.Split(strings.TrimRight(text[start:end], "\n"), "\n") {
		name, _, _ := strings.Cut(line, ":")
		switch strings.ToLower(name) {
		case "dn":
			line = "dn: " + two
		case "cn", "name":
			line = name + ": Lee  Ann"
		case "distinguishedname":
			line = name + ": " + two
		case "samaccountname":
			line = name + fmt.Sprintf(": s%06db", runID)
		case "objectguid":
			line = name + ":: " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("guid-%010d!", runID)))
		case "objectsid":
			continue
		}
		if strings.HasPrefix(line, " ") { // a folded continuation of a line left out
			continue
		}
		sibling = append(sibling, line)
	}
	text = text[:end] + strings.Join(sibling, "\n") + "\n\n" + text[end:]
	text = strings.Replace(text, "dn: "+team+"\n", "dn: "+team+"\nmember: "+two+"\n", 1)
	var entries int
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "# end: ") {
			fmt.Sscanf(line, "# end: %d entries", &entries)
		}
	}
	text = strings.Replace(text, fmt.Sprintf("# end: %d entries", entries), fmt.Sprintf("# end: %d entries", entries+1), 1)
	path := filepath.Join(t.TempDir(), "spaces.ldif")
	must(os.WriteFile(path, []byte(text), 0o600))

	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nldif = %q\n[target]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n[scope]\nbase_dn = %q\n",
		path, dstURL, adminDN, scope)))
	must(err)
	pw := func() (string, error) { return adminPw, nil }
	s, err := app.Open(ctx, cfg, app.Secrets{TargetBind: pw, UserPassword: func() (string, error) { return fixedPw, nil }}, app.LDAP, &bytes.Buffer{})
	must(err)
	t.Cleanup(s.Close)
	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if len(rep.NameTaken) != 1 {
		t.Fatalf("name taken: %+v\n%s", rep.NameTaken, log.String())
	}
	held, err := dst.Get(ctx, rep.NameTaken[0].TargetDN, []string{"sAMAccountName"})
	must(err)
	wantSAM := map[string]string{one: fmt.Sprintf("s%06da", runID), two: fmt.Sprintf("s%06db", runID)}[held.DN]
	if held == nil || strings.Join(held.Values("sAMAccountName"), "") != wantSAM {
		t.Fatalf("the entry added was overwritten: %+v (want %s)", held, wantSAM)
	}
	members, err := dst.Get(ctx, team, []string{"member"})
	must(err)
	if len(members.Values("member")) != 1 {
		t.Fatalf("the group's members: %v", members.Values("member"))
	}
	var diffOut bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &diffOut); err != nil || code != app.ExitDiff || !strings.Contains(diffOut.String(), "NAME_TAKEN  : 1") {
		t.Fatalf("diff (%d, %v):\n%s", code, err, diffOut.String())
	}
}

// Samba refuses HOST/X on an object when another holds http/X (sPNMappings), and takes the reverse order. The source
// is given them in that order; clone writes users before computers, so without withholding the user's http/X the
// computer's HOST/X would be refused. The computer keeps HOST/X, the user its other SPNs, and diff finds nothing.
func TestAnSPNCollidingThroughSambasAliasesDoesNotStopClone(t *testing.T) {
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
	scope := fmt.Sprintf("OU=Alias%06d,%s", runID, realmDN)
	pc, svc := "CN=PC1,"+scope, "CN=Svc,"+scope
	host, alias, other := fmt.Sprintf("HOST/a%06d.%s", runID, realm), fmt.Sprintf("http/a%06d.%s", runID, realm), fmt.Sprintf("HTTP/w%06d.%s", runID, realm)
	must(src.Add(ctx, directory.Entry{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}}}))
	must(src.Add(ctx, directory.Entry{DN: pc, Attrs: map[string][]string{"objectClass": {"computer"}, "userAccountControl": {"4096"},
		"sAMAccountName": {fmt.Sprintf("a%06dpc$", runID)}, "servicePrincipalName": {host}}}))
	must(src.Add(ctx, directory.Entry{DN: svc, Attrs: map[string][]string{"objectClass": {"user"}, "sAMAccountName": {fmt.Sprintf("a%06dsvc", runID)},
		"servicePrincipalName": {alias, other}}}))

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
	if rep.Withheld["servicePrincipalName"] != 1 {
		t.Fatalf("withheld %+v\n%s", rep.WithheldWhy, log.String())
	}
	for d, want := range map[string]string{pc: strings.ToLower(host), svc: strings.ToLower(other)} {
		e, err := dst.Get(ctx, d, []string{"servicePrincipalName"})
		must(err)
		if e == nil || strings.ToLower(strings.Join(e.Values("servicePrincipalName"), ",")) != want {
			t.Fatalf("%s on the target: %+v, want %s", d, e, want)
		}
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &out); err != nil || code != app.ExitSame {
		t.Fatalf("diff: %d %v\n%s", code, err, out.String())
	}
}

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
	"github.com/wadahiro/ldap-cronin/internal/dn"
)

// A forward link of DN-Binary syntax on group, in the shape of Exchange's authOrig (who may send to a group): check
// suggests it, schema carries it, clone writes its values with the binary part kept and creates the entry a value
// names outside the scope, and diff compares them, a removed value showing.
func TestADNBinaryLinkIsClonedAndCompared(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	attr, aux := fmt.Sprintf("acmeAuthOrig%06d", runID), fmt.Sprintf("acmeMailAux%06d", runID)
	ctx := context.Background()
	src := dial(t, srcURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	schema := "CN=Schema,CN=Configuration," + realmDN
	refresh := func() { must(src.AddValues(ctx, "", "schemaUpdateNow", []string{"1"})) }
	must(src.Add(ctx, directory.Entry{DN: "CN=" + attr + "," + schema, Attrs: map[string][]string{
		"objectClass": {"attributeSchema"}, "cn": {attr}, "lDAPDisplayName": {attr},
		"attributeID": {fmt.Sprintf("1.3.6.1.4.1.99999.12.%d", runID)}, "attributeSyntax": {"2.5.5.7"}, "oMSyntax": {"127"},
		// Object(DN-Binary): 1.2.840.113556.1.1.1.11; the linkID a new forward link is given
		"oMObjectClass": {"\x2a\x86\x48\x86\xf7\x14\x01\x01\x01\x0b"}, "linkID": {"1.2.840.113556.1.2.50"},
		"isSingleValued": {"FALSE"},
	}}))
	refresh()
	must(src.Add(ctx, directory.Entry{DN: "CN=" + aux + "," + schema, Attrs: map[string][]string{
		"objectClass": {"classSchema"}, "cn": {aux}, "lDAPDisplayName": {aux},
		"governsID": {fmt.Sprintf("1.3.6.1.4.1.99999.13.%d", runID)}, "objectClassCategory": {"3"}, "subClassOf": {"top"},
		"mayContain": {attr},
	}}))
	refresh()
	must(src.AddValues(ctx, "CN=Group,"+schema, "auxiliaryClass", []string{aux}))
	refresh()

	scope := fmt.Sprintf("OU=Mail%06d,%s", runID, realmDN)
	elsewhere := fmt.Sprintf("OU=Senders%06d,%s", runID, realmDN)
	for _, ou := range []string{scope, elsewhere} {
		must(src.Add(ctx, directory.Entry{DN: ou, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}}}))
	}
	ann, bob := "CN=Ann,"+scope, "CN=Bob,"+elsewhere
	for i, u := range []string{ann, bob} {
		must(src.Add(ctx, directory.Entry{DN: u, Attrs: map[string][]string{"objectClass": {"user"},
			"sAMAccountName": {fmt.Sprintf("m%06d%d", runID, i)}}}))
	}
	group := "CN=Staff," + scope
	must(src.Add(ctx, directory.Entry{DN: group, Attrs: map[string][]string{"objectClass": {"group"},
		"sAMAccountName": {fmt.Sprintf("m%06dg", runID)}, attr: {"B:0::" + ann, "B:8:0A0B0C0D:" + bob}}}))
	if e, err := src.Get(ctx, group, []string{attr}); err == nil && e != nil {
		t.Logf("the source returns %s as %q", attr, e.Values(attr))
	}

	open := func(extra string) *app.Session {
		cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n"+
			"[target]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n[scope]\nbase_dn = %q\n%s",
			srcURL, adminDN, dstURL, adminDN, scope, extra)))
		must(err)
		pw := func() (string, error) { return adminPw, nil }
		s, err := app.Open(ctx, cfg, app.Secrets{SourceBind: pw, TargetBind: pw, UserPassword: func() (string, error) { return fixedPw, nil }}, app.LDAP, &bytes.Buffer{})
		must(err)
		t.Cleanup(s.Close)
		return s
	}

	// Not named: check counts it as an attribute clone leaves behind, not as one only the server writes.
	var report bytes.Buffer
	_, err := open("").Check(ctx, app.CheckOptions{Config: "c.toml"}, &report)
	must(err)
	if !strings.Contains(report.String(), "extra_include = [") || !strings.Contains(report.String(), `"`+attr+`"`) {
		t.Fatalf("check does not suggest %s:\n%s", attr, report.String())
	}

	s := open(fmt.Sprintf("[attributes]\nextra_include = [%q]\n", attr))
	must(s.Schema(ctx, true, &bytes.Buffer{}, &bytes.Buffer{}))
	var log bytes.Buffer
	report1, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if report1.ReferencedKinds["user"] != 1 {
		t.Errorf("Bob, outside the scope, is created as the value names him: %+v", report1.ReferencedKinds)
	}
	dst := dial(t, dstURL)
	e, err := dst.Get(ctx, group, []string{attr})
	must(err)
	if e == nil {
		t.Fatal("the group is not on the target")
	}
	t.Logf("the target returns %s as %q", attr, e.Values(attr))
	got := map[string]bool{}
	for _, v := range e.Values(attr) {
		got[dn.NormalizeRef(v)] = true
	}
	for _, want := range []string{"B:0::" + ann, "B:8:0A0B0C0D:" + bob} {
		if !got[dn.NormalizeRef(want)] {
			t.Errorf("the target lacks %s", want)
		}
	}
	if b, err := dst.Get(ctx, bob, []string{"objectClass"}); err != nil || b == nil {
		t.Fatalf("Bob is not on the target: %v", err)
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &out); err != nil || code != app.ExitSame {
		t.Fatalf("right after the clone (%d, %v):\n%s", code, err, out.String())
	}
	if log.Reset(); true {
		if _, err := s.Clone(ctx, false, &log, &log); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(log.String(), "update "+group) {
			t.Errorf("a second clone rewrites the values:\n%s", log.String())
		}
	}

	must(dst.Replace(ctx, group, map[string][]string{attr: {"B:0::" + ann}})) // Bob's value removed
	out.Reset()
	code, err := s.Diff(ctx, app.DiffOutput{}, &out)
	must(err)
	if code != app.ExitDiff || !strings.Contains(out.String(), attr) || !strings.Contains(out.String(), "Bob") {
		t.Fatalf("a removed value shows (%d):\n%s", code, out.String())
	}
}

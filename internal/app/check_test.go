package app

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"
)

// check reads the source and says, per kind, which attributes its entries hold that clone leaves behind, with the
// [attributes] line that copies them; -attrs adds the table of every attribute and what clone does with it.
func TestCheckShowsWhatCloneLeavesBehindAndTheLineThatCopiesIt(t *testing.T) {
	w := newWorld()
	w.src.Lookup(alice).Attrs["acmeEmployeeCode"] = []string{"E1"}
	w.src.Lookup(alice).Attrs["unicodePwd"] = []string{"secret"}
	// AD hands a large member over as member;range=0-1499 when every attribute is asked for.
	w.src.Put("CN=Big,OU=Users,"+base, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Big"}, "member;range=0-1499": {alice}})
	s := w.open(t, ``)
	var out bytes.Buffer
	code, err := s.Check(context.Background(), CheckOptions{NoTarget: true, Attrs: true, Config: "c.toml"}, &out)
	if err != nil || code != CheckReady {
		t.Fatalf("%d %v", code, err)
	}
	got := out.String()
	for _, want := range []string{
		`(?m)^target: not read \(-no-target\)$`,
		// (the fake gives every entry an entryUUID, which no schema here says only the server writes)
		`(?m)^\[user\] 1 entries; \d attributes they hold are not copied \(no allow list names them\):\n  acmeEmployeeCode\s+1$`,
		`(?m)^\[computer\] 0 entries: clone copies every attribute they hold that a client can write$`,
		// Without a schema to say what a client can write (this fake has none; AD and a dump of it do), what is
		// held and not named is all suggested.
		`(?m)^       extra_include = \[.*"acmeEmployeeCode".*\]$`,
		`(?m)^  \d\. check again: ldap-cronin check -config c\.toml$`,
		`(?m)^  \d\. clone: ldap-cronin clone -config c\.toml$`,
		// -attrs
		`\[user\] 1 entries under ` + regexp.QuoteMeta(base),
		`(?m)^  not copied\s+acmeEmployeeCode\s+1$`,
		`(?m)^  copied\s+title\s+1$`,
		`(?m)^  copied\s+member\s+1$`,
		`(?m)^  copied      no entry holds these \d+:$`,
		`(?m)^ {16}(\S+, )*department,`, // an attribute of the allow list no entry holds is named too
		`(?m)^  never\s+unicodePwd\s+1  credential$`,
		`(?m)^  never\s+objectGUID\s+1  managed by the server$`,
	} {
		if !regexp.MustCompile(want).MatchString(got) {
			t.Errorf("missing %s in\n%s", want, got)
		}
	}
	if strings.Contains(got, "secret") || strings.Contains(got, "E1") {
		t.Fatalf("no value is ever printed:\n%s", got)
	}
	if strings.Contains(got, `"unicodePwd"`) {
		t.Fatalf("a credential is never suggested:\n%s", got)
	}
	if len(w.dialed) != 1 {
		t.Fatalf("with -no-target only the source is read: %v", w.dialed)
	}
}

// With the target, check says what its schema lacks, keeps out of the suggestion what only the server writes, and
// exits 1 when clone would refuse to start (an attribute the allow lists name is missing on the target).
func TestCheckSaysWhatTheTargetLacksAndWhenCloneWouldRefuse(t *testing.T) {
	w := newWorld()
	may := []string{"sAMAccountName", "title", "userAccountControl", "acmeCode", "acmeSponsor", "acmeStamp"}
	withClasses(w.src, may)
	withClasses(w.dst, may)
	for _, n := range []string{"cn", "objectClass", "sAMAccountName", "title", "userAccountControl", "adminDisplayName", "acmeCode", "acmeSponsor", "acmeStamp"} {
		e := map[string][]string{"objectClass": {"attributeSchema"}, "cn": {n}, "lDAPDisplayName": {n}, "attributeID": {"1.9." + n}, "attributeSyntax": {"2.5.5.12"}}
		switch n {
		case "acmeStamp":
			e["systemOnly"] = []string{"TRUE"}
		case "adminDisplayName": // the marker
			e["isSingleValued"], e["searchFlags"] = []string{"TRUE"}, []string{"1"}
		}
		w.src.Put("CN="+n+","+schemaNC, e)
		if !strings.HasPrefix(n, "acme") {
			w.dst.Put("CN="+n+","+schemaNC, e)
		}
	}
	w.src.Lookup(alice).Attrs["acmeCode"] = []string{"E-1"}
	w.src.Lookup(alice).Attrs["acmeStamp"] = []string{"1"}
	s := w.openWith(t, "[attributes]\nmode = \"allowlist\"\nextra_include = [\"acmeSponsor\"]\n")
	var out bytes.Buffer
	code, err := s.Check(context.Background(), CheckOptions{Config: "c.toml"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if code != CheckBlocked {
		t.Errorf("clone would refuse, so check exits %d, not %d:\n%s", CheckBlocked, code, got)
	}
	for _, want := range []string{
		`(?m)^target: ldaps://dst:636$`,
		`(?m)^  acmeCode\s+1  the target schema lacks it$`,
		`(?m)^  \(and 1 more only the server writes; -attrs lists every attribute\)$`,
		`(?m)^clone refuses to start: the target schema lacks 1 attributes the allow lists name:\n  acmeSponsor \(ou, group, user`,
		`(?m)^       extra_include = \["acmeCode", "acmeSponsor"\]$`,
		`(?m)^     or copy every attribute a client can write: \[attributes\] mode = "all"$`,
		`(?m)^  \d\. give the target the source's definitions: ldap-cronin schema -config c\.toml -apply$`,
	} {
		if !regexp.MustCompile(want).MatchString(got) {
			t.Errorf("missing %s in\n%s", want, got)
		}
	}
	if strings.Contains(got, `"acmeStamp"`) {
		t.Fatalf("what only the server writes is never suggested:\n%s", got)
	}
}

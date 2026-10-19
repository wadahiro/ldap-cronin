package app

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"
)

// list-attrs -config reads the source and says, per kind, which attributes its entries hold and what clone does
// with each: a schema extension of the deployment shows as not copied, with the number of entries holding it.
func TestListAttrsShowsWhatTheSourceHoldsAndWhatCloneLeavesBehind(t *testing.T) {
	w := newWorld()
	w.src.Lookup(alice).Attrs["acmeEmployeeCode"] = []string{"E1"}
	w.src.Lookup(alice).Attrs["unicodePwd"] = []string{"secret"}
	// AD hands a large member over as member;range=0-1499 when every attribute is asked for.
	w.src.Put("CN=Big,OU=Users,"+base, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Big"}, "member;range=0-1499": {alice}})
	s := w.open(t, ``)
	var out bytes.Buffer
	if err := s.ListAttrs(context.Background(), false, false, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		`\[user\] 1 entries under ` + regexp.QuoteMeta(base),
		`(?m)^  not copied\s+acmeEmployeeCode\s+1$`,
		`(?m)^  copied\s+title\s+1$`,
		`(?m)^  copied\s+member\s+1$`,
		`(?m)^  \(and \d+ attributes of the allow list that no entry holds; -all lists them\)$`,
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
	if strings.Index(got, "not copied") > strings.Index(got, "  copied ") {
		t.Fatalf("what clone leaves behind comes first:\n%s", got)
	}
	out.Reset()
	if err := s.ListAttrs(context.Background(), false, true, &out); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^  copied\s+department\s+0$`).MatchString(out.String()) {
		t.Fatalf("-all lists the allow list's attributes no entry holds:\n%s", out.String())
	}
	if len(w.dialed) != 1 {
		t.Fatalf("without -target only the source is read: %v", w.dialed)
	}
}

func TestListAttrsWithTargetNotesWhatTheTargetSchemaLacks(t *testing.T) {
	w := newWorld()
	w.src.Lookup(alice).Attrs["acmeEmployeeCode"] = []string{"E1"}
	schemaNC := "CN=Schema,CN=Configuration," + domain
	w.dst.Put("", map[string][]string{"schemaNamingContext": {schemaNC}})
	for _, n := range []string{"title", "cn", "sAMAccountName"} {
		w.dst.Put("CN="+n+","+schemaNC, map[string][]string{"objectClass": {"attributeSchema"}, "lDAPDisplayName": {n}})
	}
	s := w.open(t, ``)
	var out bytes.Buffer
	if err := s.ListAttrs(context.Background(), true, false, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !regexp.MustCompile(`(?m)^  not copied\s+acmeEmployeeCode\s+1  not in the target schema$`).MatchString(got) ||
		!regexp.MustCompile(`(?m)^  copied\s+title\s+1$`).MatchString(got) {
		t.Fatalf("%s", got)
	}
}

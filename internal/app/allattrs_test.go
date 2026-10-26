package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/fakedir"
)

const schemaNC = "CN=Schema,CN=Configuration," + domain

// withClasses gives d a schema naming context with the classes of the AD kinds, where user may hold userMay.
func withClasses(d *fakedir.Dir, userMay []string) {
	d.Put("", map[string][]string{"schemaNamingContext": {schemaNC}})
	for _, c := range []string{"top", "organizationalUnit", "group", "user", "computer", "contact"} {
		e := map[string][]string{"objectClass": {"classSchema"}, "cn": {c}, "lDAPDisplayName": {c}, "governsID": {"1.8." + c}, "subClassOf": {"top"}}
		switch c {
		case "user":
			e["mayContain"] = userMay
		case "group":
			e["mayContain"] = []string{"member", "description"}
		case "computer":
			e["subClassOf"] = []string{"user"}
		case "top":
			e["systemMustContain"] = []string{"cn", "objectClass"}
		}
		d.Put("CN="+c+","+schemaNC, e)
	}
}

// mode = "all" takes what the source schema lets a client write on each kind's class, without what clone never
// copies, the marker and exclude; what the target's schema lacks is left out with a note instead of stopping clone.
func TestModeAllCopiesWhatAClientCanWrite(t *testing.T) {
	w := newWorld()
	defs := map[string][]string{"systemFlags": {"16"}}
	attrs := map[string]map[string][]string{
		"cn": defs, "objectClass": defs, "sAMAccountName": defs, "title": defs, "userAccountControl": defs,
		"userPassword": defs, "objectSid": defs,
		// the marker, where clone writes what diff matches by
		"adminDisplayName": {"systemFlags": {"16"}, "attributeSyntax": {"2.5.5.12"}, "isSingleValued": {"TRUE"}, "searchFlags": {"1"}},
		"acmeCode":         nil,
		"memberOf":         {"linkID": {"3"}},
		"whenChanged":      {"systemOnly": {"TRUE"}},
		"department":       defs,
	}
	may := []string{"sAMAccountName", "title", "userAccountControl", "adminDisplayName", "userPassword", "objectSid", "acmeCode", "memberOf", "whenChanged", "department"}
	withClasses(w.src, may)
	for name, more := range attrs {
		e := map[string][]string{"objectClass": {"attributeSchema"}, "cn": {name}, "lDAPDisplayName": {name}, "attributeID": {"1.9." + name},
			"attributeSyntax": {"2.5.5.12"}}
		for k, v := range more {
			e[k] = v
		}
		w.src.Put("CN="+name+","+schemaNC, e)
		if name != "acmeCode" {
			w.dst.Put("CN="+name+","+schemaNC, e)
		}
	}
	withClasses(w.dst, may)
	w.src.Lookup(alice).Attrs["acmeCode"] = []string{"E-1"}
	w.src.Lookup(alice).Attrs["department"] = []string{"R&D"}

	s := w.openWith(t, "[attributes]\nmode = \"all\"\nexclude = [\"title\"]\n")
	user, _ := s.Job.Kind("user")
	if got := strings.Join(user.Attrs, ","); got != "objectClass,cn,ou,acmeCode,department,sAMAccountName,userAccountControl" {
		t.Fatalf("user attributes: %s", got)
	}
	if !s.Job.AllWritable {
		t.Fatal("the job says the lists are every attribute a client can write")
	}

	ctx := context.Background()
	var log bytes.Buffer
	if _, err := s.Clone(ctx, false, &bytes.Buffer{}, &log); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "the target schema lacks 1 attributes") || !strings.Contains(log.String(), "\n  acmeCode\n") {
		t.Fatalf("the attribute the target lacks is named:\n%s", log.String())
	}
	a := w.dst.Lookup(alice)
	if a.Values("acmeCode") != nil || strings.Join(a.Values("department"), "") != "R&D" {
		t.Fatalf("%v", a.Attrs)
	}
	var warn, out bytes.Buffer
	s.Warn = &warn
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitSame {
		t.Fatalf("%d %v\n%s", code, err, out.String())
	}
	if !strings.Contains(warn.String(), "acmeCode") || !strings.Contains(out.String(), "user : 6, every attribute a client can write on user") {
		t.Fatalf("warn:\n%s\nout:\n%s", warn.String(), out.String())
	}

	// check names what exclude leaves behind, and not what only the server writes.
	w.src.Lookup(alice).Attrs["whenChanged"] = []string{"20261021091233.0Z"}
	w.src.Lookup(alice).Attrs["memberOf"] = []string{"CN=G," + base}
	var report bytes.Buffer
	if _, err := s.Check(ctx, CheckOptions{Config: "c.toml"}, &report); err != nil {
		t.Fatal(err)
	}
	got := report.String()
	if !strings.Contains(got, "[user] 1 entries; 1 attributes they hold are not copied:\n  title        1  [attributes] exclude names it\n") {
		t.Fatalf("the excluded attribute is named:\n%s", got)
	}
	if strings.Contains(got, "  whenChanged ") || strings.Contains(got, "  memberOf ") || strings.Contains(got, "extra_include") {
		t.Fatalf("what only the server writes is not listed, and mode = \"all\" suggests no extra_include:\n%s", got)
	}
}

// A profile that cannot tell what a client may write refuses mode = "all" instead of copying nothing.
func TestModeAllNeedsAProfileThatReadsTheSchema(t *testing.T) {
	w := newWorld()
	_, err := w.tryOpen("[attributes]\nmode = \"all\"\n")
	if err == nil || !strings.Contains(err.Error(), "needs the source schema, which cannot be read") {
		t.Fatalf("a source without a readable schema: %v", err)
	}
}

// The default on AD is every attribute a client can write, gPLink included: it is copied as it is and compared,
// and check notes that the GPOs it links are not copied. What no client can write is "never" in -attrs, not "not
// copied".
func TestTheDefaultCopiesGPLinkAndNotesTheGPOs(t *testing.T) {
	w := newWorld()
	withClasses(w.src, []string{"title"})
	ou := w.src.Lookup("CN=organizationalUnit," + schemaNC)
	ou.Attrs["mayContain"] = []string{"gPLink", "description"}
	for _, name := range []string{"gPLink", "description", "title", "directReports"} {
		e := map[string][]string{"objectClass": {"attributeSchema"}, "cn": {name}, "lDAPDisplayName": {name}, "attributeID": {"1.9." + name},
			"attributeSyntax": {"2.5.5.12"}}
		if name == "directReports" {
			e["linkID"], e["attributeSyntax"] = []string{"43"}, []string{"2.5.5.1"}
		}
		w.src.Put("CN="+name+","+schemaNC, e)
	}
	w.src.Lookup("OU=Users," + base).Attrs["gPLink"] = []string{"[LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system," + domain + ";0]"}
	w.src.Lookup(alice).Attrs["directReports"] = []string{"CN=Bob," + base}
	s := w.openWith(t, "")
	if !s.Job.AllWritable {
		t.Fatal("the default on AD is every attribute a client can write")
	}
	k, _ := s.Job.Kind("ou")
	if got := strings.Join(k.Attrs, ","); !strings.Contains(got, "gPLink") || !strings.Contains(got, "description") {
		t.Fatalf("ou attributes: %s", got)
	}
	var out bytes.Buffer
	if _, err := s.Check(context.Background(), CheckOptions{NoTarget: true, Attrs: true, Config: "c.toml"}, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"[ou] 2 entries: clone copies every attribute they hold that a client can write (mode = \"all\")\n",
		"  note: gPLink (1 entries): copied as it is; the GPOs it links are not",
		"never       directReports",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("check lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "not copied  directReports") {
		t.Errorf("a back link is never copied, not left behind:\n%s", got)
	}
	var log bytes.Buffer
	if _, err := s.Clone(context.Background(), false, &log, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if got := w.dst.Lookup("OU=Users," + base).Values("gPLink"); len(got) != 1 || !strings.HasPrefix(got[0], "[LDAP://cn={31B2F340") {
		t.Fatalf("gPLink on the target: %v", got)
	}
	w.dst.Lookup("OU=Users," + base).Attrs["gPLink"] = []string{"[LDAP://cn={0},cn=policies,cn=system," + domain + ";0]"}
	out.Reset()
	if code, err := s.Diff(context.Background(), DiffOutput{}, &out); err != nil || code != ExitDiff || !strings.Contains(out.String(), "gPLink") {
		t.Fatalf("diff compares gPLink (%d, %v):\n%s", code, err, out.String())
	}
}

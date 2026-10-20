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
}

// A profile that cannot tell what a client may write refuses mode = "all" instead of copying nothing.
func TestModeAllNeedsAProfileThatReadsTheSchema(t *testing.T) {
	w := newWorld()
	_, err := w.tryOpen("[attributes]\nmode = \"all\"\n")
	if err == nil || !strings.Contains(err.Error(), "source schema cannot be read") {
		t.Fatalf("a source without a readable schema: %v", err)
	}
}

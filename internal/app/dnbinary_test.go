package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/dump"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// A DN-Binary attribute is a reference: mode = "all" takes it, clone writes each
// value with its binary part and creates the entry it names outside the scope, and diff compares it, translating
// the DN alone. A credential of the same syntax (msDS-KeyCredentialLink) stays out.
func TestADNBinaryAttributeIsAReference(t *testing.T) {
	w := newWorld()
	bob := "CN=Bob,OU=Elsewhere," + domain
	w.src.Put("OU=Elsewhere,"+domain, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Elsewhere"}})
	w.src.Put(bob, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {"Bob"},
		"sAMAccountName": {"bob"}, "userAccountControl": {"512"}})
	carol := "CN=Carol,OU=Users," + base
	w.src.Put(carol, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {"Carol"},
		"sAMAccountName": {"carol"}, "userAccountControl": {"512"}})
	plain := map[string][]string{"systemFlags": {"16"}}
	attrs := map[string]map[string][]string{
		"cn": plain, "objectClass": plain, "sAMAccountName": plain, "userAccountControl": plain,
		"adminDisplayName":       {"attributeSyntax": {"2.5.5.12"}, "isSingleValued": {"TRUE"}, "searchFlags": {"1"}},
		"acmeAuthOrig":           {"attributeSyntax": {"2.5.5.7"}, "linkID": {"110"}},
		"acmeAuthOrigBL":         {"attributeSyntax": {"2.5.5.1"}, "linkID": {"111"}},
		"msDS-KeyCredentialLink": {"attributeSyntax": {"2.5.5.7"}, "linkID": {"2220"}},
	}
	may := []string{"sAMAccountName", "userAccountControl", "adminDisplayName", "acmeAuthOrig", "acmeAuthOrigBL", "msDS-KeyCredentialLink"}
	for _, d := range []*fakedir.Dir{w.src, w.dst} {
		withClasses(d, may)
		for name, more := range attrs {
			e := map[string][]string{"objectClass": {"attributeSchema"}, "cn": {name}, "lDAPDisplayName": {name}, "attributeID": {"1.9." + name},
				"attributeSyntax": {"2.5.5.12"}}
			for k, v := range more {
				e[k] = v
			}
			d.Put("CN="+name+","+schemaNC, e)
		}
	}
	a := w.src.Lookup(alice).Attrs
	a["acmeAuthOrig"] = []string{"B:0::" + carol, "B:8:0A0B0C0D:" + bob}
	a["msDS-KeyCredentialLink"] = []string{"B:8:00112233:" + alice}

	s := w.openWith(t, "[attributes]\nmode = \"all\"\n")
	user, _ := s.Job.Kind("user")
	if got := strings.Join(user.Attrs, ","); !strings.Contains(got, "acmeAuthOrig") || strings.Contains(got, "KeyCredentialLink") || strings.Contains(got, "acmeAuthOrigBL") {
		t.Fatalf("user attributes: %s", got)
	}
	ctx := context.Background()
	report, err := s.Clone(ctx, false, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if report.ReferencedKinds["user"] != 1 || w.dst.Lookup(bob) == nil {
		t.Fatalf("Bob, named inside a DN-Binary value, is created: %+v", report.ReferencedKinds)
	}
	got := w.dst.Lookup(alice).Values("acmeAuthOrig")
	if strings.Join(got, "|") != "B:0::"+carol+"|B:8:0A0B0C0D:"+bob {
		t.Fatalf("the values as the source has them: %q", got)
	}
	if w.dst.Lookup(alice).Values("msDS-KeyCredentialLink") != nil {
		t.Fatal("a credential is never copied")
	}
	if code, err := s.Diff(ctx, DiffOutput{}, &bytes.Buffer{}); err != nil || code != ExitSame {
		t.Fatalf("right after the clone: %d %v", code, err)
	}
	// The server may return the empty binary part or not: the same value.
	w.dst.Lookup(alice).Attrs["acmeAuthOrig"] = []string{carol, "B:8:0a0b0c0d:" + bob}
	if code, err := s.Diff(ctx, DiffOutput{}, &bytes.Buffer{}); err != nil || code != ExitSame {
		t.Fatalf("B:0::<DN> is <DN>, and hex has no case: %d %v", code, err)
	}
	// Another binary part, or a value removed, is a difference.
	w.dst.Lookup(alice).Attrs["acmeAuthOrig"] = []string{carol, "B:8:FFFFFFFF:" + bob}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitDiff || !strings.Contains(out.String(), "acmeAuthOrig") {
		t.Fatalf("another binary part: %d %v\n%s", code, err, out.String())
	}

	// With the allow lists, check suggests it as what clone leaves behind (not as what only the server writes),
	// and not the credential.
	var checked bytes.Buffer
	if _, err := w.openWith(t, "").Check(ctx, CheckOptions{Config: "c.toml"}, &checked); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(checked.String(), `"acmeAuthOrig"`) || strings.Contains(checked.String(), "KeyCredentialLink") {
		t.Fatalf("check:\n%s", checked.String())
	}

	// A dump carries the entry a DN-Binary value names outside its base, as it does a member's.
	var dumped bytes.Buffer
	counts, err := dump.Write(ctx, w.src, profile.AD, dump.Options{BaseDN: base, Server: "ldaps://src:636", Version: "test"}, &dumped)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dumped.String(), "dn: "+bob+"\n") || counts.Referenced == 0 {
		t.Fatalf("the dump lacks Bob (%+v)", counts)
	}
}

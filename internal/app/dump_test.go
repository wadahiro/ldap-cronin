package app

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dump"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// A clone from a dump gives what a clone from the source gives: the entries under the base DN, the parents above it,
// and what a reference names outside it (a manager, a member). The dump never holds a credential, masks what it
// was told to, and is read with no password asked and no server dialed.
func TestACloneFromADumpIsTheCloneFromTheSource(t *testing.T) {
	// Every AD object has its objectCategory, which the dump's filters evaluate as AD does (the fake directory of the
	// tests matches by keyword and lets it be missing).
	person := "CN=Person,CN=Schema,CN=Configuration," + domain
	seed := func(w *world) {
		w.src.Lookup(domain).Attrs["objectGUID"] = []string{"0123456789abcdef"}
		w.src.Put("OU=Elsewhere,"+domain, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Elsewhere"}})
		w.src.Put("CN=Boss,OU=Elsewhere,"+domain, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"},
			"cn": {"Boss"}, "sAMAccountName": {"boss"}, "userAccountControl": {"512"}, "manager": {alice}, "objectCategory": {person}})
		// A group outside the base DN, a member of Team, whose own member is further outside: clone creates the group
		// without its own references, so the dump does not need that member.
		w.src.Put("OU=Far,"+domain, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Far"}})
		w.src.Put("CN=Farther,OU=Far,"+domain, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"},
			"cn": {"Farther"}, "sAMAccountName": {"farther"}, "userAccountControl": {"512"}, "objectCategory": {person}})
		w.src.Put("CN=Outside,OU=Elsewhere,"+domain, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Outside"},
			"sAMAccountName": {"outside"}, "member": {"CN=Farther,OU=Far," + domain}})
		w.src.Put("CN=Team,OU=Users,"+base, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Team"},
			"sAMAccountName": {"team"}, "member": {alice, "CN=Boss,OU=Elsewhere," + domain, "CN=Outside,OU=Elsewhere," + domain,
				"CN=Gone,OU=Elsewhere," + domain}})
		a := w.src.Lookup(alice).Attrs
		a["objectCategory"] = []string{person}
		a["manager"] = []string{"CN=Boss,OU=Elsewhere," + domain}
		a["mail"] = []string{"alice@example.com"}
		a["unicodePwd"] = []string{"secret"}
		a["ms-Mcs-AdmPwd"] = []string{"laps"}
	}

	live := newWorld()
	seed(live)
	liveReport, err := live.open(t, "").Clone(context.Background(), false, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}

	src := newWorld()
	seed(src)
	var out bytes.Buffer
	counts, err := dump.Write(context.Background(), src.src, profile.AD, dump.Options{BaseDNs: []string{base}, MaskValue: "********",
		Masked: []string{"mail"}, Server: "ldaps://src:636", Version: "test"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Referenced != 3 { // Boss, Outside and the OU above them; not Farther, nor Gone, which is nowhere
		t.Fatalf("referenced: %+v", counts)
	}
	text := out.String()
	for _, never := range []string{"secret", "laps", "alice@example.com"} {
		if strings.Contains(text, never) {
			t.Fatalf("the dump holds %q:\n%s", never, text)
		}
	}
	for _, want := range []string{"# excluded (credentials, never dumped):\n", "#   unicodePwd\n", "# masked (value: ********):\n#   mail\n", "\n# end: "} {
		if !strings.Contains(text, want) {
			t.Fatalf("the header lacks %q:\n%s", want, text)
		}
	}
	path := filepath.Join(t.TempDir(), "prod.ldif")
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	w := newWorld() // its source is never dialed: the dump stands for it
	cfg, err := config.Parse([]byte("[source]\nldif = \"" + path + "\"\n[target]\nurl = \"ldaps://dst:636\"\nbind_dn = \"CN=a\"\n" +
		"[scope]\nprofile = \"ad\"\nbase_dn = \"" + base + "\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	var warn bytes.Buffer
	s, err := Open(context.Background(), cfg, w.secrets(), w.dial, &warn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !strings.Contains(warn.String(), "source: the dump "+path+" of ldaps://src:636") || !strings.Contains(warn.String(), "masked in the dump: mail") {
		t.Fatalf("which dump: %s", warn.String())
	}
	report, err := s.Clone(context.Background(), false, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(report.Unwritten, report.ReferencedKinds, report.Added) != fmt.Sprint(liveReport.Unwritten, liveReport.ReferencedKinds, liveReport.Added) {
		t.Fatalf("the summaries differ:\nfrom the dump %+v\nfrom the source %+v", report, liveReport)
	}
	if strings.Join(w.asked, ",") != "user,target" || len(w.dialed) != 1 || strings.Contains(w.dialed[0], "src") {
		t.Fatalf("no source password, no source dialed: asked %v, dialed %v", w.asked, w.dialed)
	}
	if got, want := snapshot(w.dst), snapshot(live.dst); got != want {
		t.Fatalf("from the dump:\n%s\n\nfrom the source:\n%s", got, want)
	}
	if code, err := s.Diff(context.Background(), DiffOutput{}, &bytes.Buffer{}); err != nil || code != ExitSame {
		t.Fatalf("diff against the dump: %d %v", code, err)
	}
}

// snapshot is the target's entries with what the target assigns itself left out, mail aside (masked from the dump,
// copied from the source).
func snapshot(d *fakedir.Dir) string {
	var lines []string
	for _, e := range d.Entries {
		var attrs []string
		for n, v := range e.Attrs {
			switch strings.ToLower(n) {
			case "objectguid", "entryuuid", "mail", "pwdlastset":
				continue
			}
			sorted := append([]string(nil), v...)
			sort.Strings(sorted)
			attrs = append(attrs, strings.ToLower(n)+"="+strings.Join(sorted, "|"))
		}
		sort.Strings(attrs)
		lines = append(lines, strings.ToLower(e.DN)+" "+strings.Join(attrs, " "))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

var _ directory.Directory = (*fakedir.Dir)(nil)

// With configuration_refs = "clone", a clone from a dump creates the address list a value names, and the
// containers above it, as a clone from the source does: the dump holds them, with the schema that says what a
// client may write on them.
func TestConfigurationRefsFromADump(t *testing.T) {
	const schemaNC = "CN=Schema,CN=Configuration," + domain
	configNC := "CN=Configuration," + domain
	list := "CN=All Users,CN=Address Lists,CN=Services," + configNC
	seed := func(w *world) {
		w.src.Put("", map[string][]string{"schemaNamingContext": {schemaNC}, "configurationNamingContext": {configNC}})
		w.src.Lookup(domain).Attrs["objectGUID"] = []string{"0123456789abcdef"}
		for _, a := range []string{"cn", "objectClass", "displayName", "seeAlso"} {
			syntax := "2.5.5.12"
			if a == "seeAlso" {
				syntax = "2.5.5.1"
			}
			w.src.Put("CN="+a+","+schemaNC, map[string][]string{"objectClass": {"attributeSchema"}, "lDAPDisplayName": {a}, "attributeSyntax": {syntax}})
		}
		for _, c := range []string{"top", "container", "addressBookContainer", "user"} {
			e := map[string][]string{"objectClass": {"classSchema"}, "lDAPDisplayName": {c}, "subClassOf": {"top"}}
			switch c {
			case "top":
				e["systemMustContain"] = []string{"cn", "objectClass"}
			case "addressBookContainer":
				e["mayContain"] = []string{"displayName"}
			case "user":
				e["mayContain"] = []string{"seeAlso"}
			}
			w.src.Put("CN="+c+","+schemaNC, e)
		}
		w.src.Put(configNC, map[string][]string{"objectClass": {"top", "configuration"}, "cn": {"Configuration"}})
		w.src.Put("CN=Services,"+configNC, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Services"}})
		w.src.Put("CN=Address Lists,CN=Services,"+configNC, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Address Lists"}})
		w.src.Put(list, map[string][]string{"objectClass": {"top", "addressBookContainer"}, "cn": {"All Users"}, "displayName": {"All Users"}})
		w.src.Lookup(alice).Attrs["seeAlso"] = []string{list}
		w.src.Lookup(alice).Attrs["objectCategory"] = []string{"CN=Person," + schemaNC}
		w.dst.Put("", map[string][]string{"configurationNamingContext": {configNC}})
		w.dst.Put(configNC, map[string][]string{"objectClass": {"top", "configuration"}, "cn": {"Configuration"}})
		w.dst.Put("CN=Services,"+configNC, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Services"}})
	}
	const more = "configuration_refs = \"clone\"\n[attributes]\nmode = \"allowlist\"\nextra_include = [\"seeAlso\"]\n"

	live := newWorld()
	seed(live)
	cfgLive, err := config.Parse([]byte("[source]\nurl = \"ldaps://src:636\"\nbind_dn = \"CN=a\"\n[target]\nurl = \"ldaps://dst:636\"\nbind_dn = \"CN=a\"\n" +
		"[scope]\nprofile = \"ad\"\nbase_dn = \"" + base + "\"\n" + more))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), cfgLive, live.secrets(), live.dial, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Clone(context.Background(), false, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if live.dst.Lookup(list) == nil {
		t.Fatal("the live clone creates the list")
	}

	src := newWorld()
	seed(src)
	var out bytes.Buffer
	if _, err := dump.Write(context.Background(), src.src, profile.AD, dump.Options{BaseDNs: []string{base}, Server: "ldaps://src:636"}, &out); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "prod.ldif")
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	w := newWorld()
	seed(w)
	cfg, err := config.Parse([]byte("[source]\nldif = \"" + path + "\"\n[target]\nurl = \"ldaps://dst:636\"\nbind_dn = \"CN=a\"\n" +
		"[scope]\nprofile = \"ad\"\nbase_dn = \"" + base + "\"\n" + more))
	if err != nil {
		t.Fatal(err)
	}
	d, err := Open(context.Background(), cfg, w.secrets(), w.dial, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.Clone(context.Background(), false, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got, want := snapshot(w.dst), snapshot(live.dst); got != want {
		t.Fatalf("from the dump:\n%s\n\nfrom the source:\n%s", got, want)
	}
}

package ldifdir

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

const root = "DC=ad,DC=example,DC=com"

// dump is a small dump as ldap-cronin dump writes one: the header, the root DSE, the classSchema entries objectCategory
// short names resolve through, a user, a computer, a group, a contact, a built-in and an OU.
func dump(entries int, end bool) string {
	body := `dn:
supportedCapabilities: 1.2.840.113556.1.4.800

dn: CN=Person,CN=Schema,CN=Configuration,` + root + `
objectClass: classSchema
lDAPDisplayName: person
defaultObjectCategory: CN=Person,CN=Schema,CN=Configuration,` + root + `

dn: CN=Organizational-Unit,CN=Schema,CN=Configuration,` + root + `
objectClass: classSchema
lDAPDisplayName: organizationalUnit
defaultObjectCategory: CN=Organizational-Unit,CN=Schema,CN=Configuration,` + root + `

dn: OU=IDM,` + root + `
objectClass: top
objectClass: organizationalUnit
objectCategory: CN=Organizational-Unit,CN=Schema,CN=Configuration,` + root + `
ou: IDM

dn: CN=Alice,OU=IDM,` + root + `
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectCategory: CN=Person,CN=Schema,CN=Configuration,` + root + `
department: IT
employeeType: staff
userAccountControl: 512
uSNChanged: 120
whenChanged: 20261021091233.0Z
objectGUID:: AAECAwQFBgcICQoLDA0ODw==
entryUUID: 0e8c3a3e-0000-0000-0000-000000000001
description: a long description that
  goes on

dn: CN=Bob\2C Jr.,OU=IDM,` + root + `
objectClass: user
objectCategory: CN=Person,CN=Schema,CN=Configuration,` + root + `
department: Sales
userAccountControl: 66050
uSNChanged: 99
whenChanged: 20250101000000.0Z
employeeType: external
manager: CN=Alice,OU=IDM,` + root + `

dn: CN=PC01,OU=IDM,` + root + `
objectClass: user
objectClass: computer
objectCategory: CN=Computer,CN=Schema,CN=Configuration,` + root + `

dn: CN=Eng,OU=IDM,` + root + `
objectClass: group
groupType: -2147483646
member: CN=Alice,OU=IDM,` + root + `

dn: CN=Ext,OU=IDM,` + root + `
objectClass: contact

dn: CN=Administrator,OU=IDM,` + root + `
objectClass: user
objectCategory: CN=Person,CN=Schema,CN=Configuration,` + root + `
isCriticalSystemObject: TRUE
`
	head := Magic + "\n# server: ldaps://dc01:636\n# base-dn: OU=IDM," + root + "\n# masked (value: ********):\n#   mail\n" +
		"# operational:\n#   entryUUID\n#\n"
	if end {
		body += "\n# end: " + strconv.Itoa(entries) + " entries\n"
	}
	return head + body
}

// read writes text to a file (compressed with gz) and opens it.
func read(t *testing.T, text string, gz bool) (*Dir, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dump.ldif")
	var data []byte = []byte(text)
	if gz {
		path += ".gz"
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		z.Write(data)
		z.Close()
		data = b.Bytes()
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return Open(path)
}

func open(t *testing.T) *Dir {
	t.Helper()
	d, err := read(t, dump(10, true), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

func names(t *testing.T, d *Dir, filter string) string {
	t.Helper()
	var got []string
	if err := d.Walk(context.Background(), "OU=IDM,"+root, filter, []string{directory.NoAttrs}, func(e directory.Entry) error {
		cn, _, _ := strings.Cut(e.DN, ",")
		got = append(got, cn)
		return nil
	}); err != nil {
		t.Fatalf("%s: %v", filter, err)
	}
	sort.Strings(got)
	return strings.Join(got, " ")
}

// Every filter the tool sends, and the documented [scope.filters] examples, select what a directory server selects.
func TestFiltersSelectAsTheServerDoes(t *testing.T) {
	d := open(t)
	const system = "(!(isCriticalSystemObject=TRUE))"
	for filter, want := range map[string]string{
		"(&(objectClass=organizationalUnit)" + system + ")":                             "OU=IDM",
		"(&(objectCategory=organizationalUnit)" + system + ")":                          "OU=IDM",
		"(&(objectClass=group)" + system + ")":                                          "CN=Eng",
		"(&(&(objectCategory=person)(objectClass=user))" + system + ")":                 "CN=Alice CN=Bob\\2C Jr.",
		"(&(objectCategory=computer)" + system + ")":                                    "CN=PC01",
		"(&(objectClass=contact)" + system + ")":                                        "CN=Ext",
		"(&(&(objectCategory=person)(objectClass=user))(|(member=*)(manager=*)))":       "CN=Bob\\2C Jr.",
		"(!(|(objectClass=organizationalUnit)(objectClass=group)(objectClass=user)))":   "CN=Ext",
		"(&(objectCategory=person)(objectClass=user)(department=IT))":                   "CN=Alice",
		"(&(objectCategory=person)(objectClass=user)(!(employeeType=external)))":        "CN=Administrator CN=Alice",
		"(manager=cn=alice,ou=idm,dc=ad,dc=example,dc=com)":                             "CN=Bob\\2C Jr.",
		"(objectGUID=\\00\\01\\02\\03\\04\\05\\06\\07\\08\\09\\0a\\0b\\0c\\0d\\0e\\0f)": "CN=Alice",
		"(cn=*)":                     "",
		"(description=a long*goes*)": "CN=Alice",
		"(department=s*s)":           "CN=Bob\\2C Jr.",
		// Ordering: integers as numbers (99 < 120 though "99" > "120" as text), generalized times as text.
		"(uSNChanged>=100)":                "CN=Alice",
		"(uSNChanged<=99)":                 "CN=Bob\\2C Jr.",
		"(whenChanged>=20260101000000.0Z)": "CN=Alice",
		"(&(objectClass=user)(sn>=a))":     "",
		// AD's bitwise rules: disabled (2) and password never expires (65536), the security groups (0x80000000).
		"(userAccountControl:1.2.840.113556.1.4.803:=2)":                              "CN=Bob\\2C Jr.",
		"(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))": "CN=Administrator CN=Alice",
		"(userAccountControl:1.2.840.113556.1.4.803:=65538)":                          "CN=Bob\\2C Jr.",
		"(userAccountControl:1.2.840.113556.1.4.804:=65538)":                          "CN=Bob\\2C Jr.",
		"(userAccountControl:1.2.840.113556.1.4.804:=514)":                            "CN=Alice CN=Bob\\2C Jr.",
		"(groupType:1.2.840.113556.1.4.803:=2147483648)":                              "CN=Eng",
	} {
		if got := names(t, d, filter); got != want {
			t.Errorf("%s: %q, want %q", filter, got, want)
		}
	}
	for _, filter := range []string{"(cn~=alice)", "(memberOf:1.2.840.113556.1.4.1941:=CN=Eng,OU=IDM," + root + ")", "(cn:dn:2.5.13.5:=IDM)", "(:1.2.840.113556.1.4.803:=2)"} {
		err := d.Walk(context.Background(), root, filter, nil, func(directory.Entry) error { return nil })
		if err == nil || !strings.Contains(err.Error(), "not supported on a dump") {
			t.Errorf("%s must be refused, not matched: %v", filter, err)
		}
	}
}

// "*" leaves out what the dump read by name as operational; named, it comes, under the name asked. Values are
// decoded (base64, folded lines). Writes are refused.
func TestEntriesReadAsFromTheServer(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	e, err := d.Get(ctx, "cn=alice,ou=idm,"+root, []string{directory.AllAttrs})
	if err != nil || e == nil {
		t.Fatalf("%v %v", e, err)
	}
	if e.Values("entryUUID") != nil || e.Values("department") == nil {
		t.Fatalf("* without the operational ones: %v", e.Attrs)
	}
	if got := e.Values("objectGUID"); len(got) != 1 || got[0] != string([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}) {
		t.Fatalf("base64: %q", got)
	}
	if got := strings.Join(e.Values("description"), ""); got != "a long description that goes on" {
		t.Fatalf("folded: %q", got)
	}
	e, _ = d.Get(ctx, "CN=Alice,OU=IDM,"+root, []string{"*", "EntryUUID"})
	if len(e.Attrs["EntryUUID"]) != 1 {
		t.Fatalf("named, under the name asked: %v", e.Attrs)
	}
	if e, _ := d.Get(ctx, "CN=Nobody,"+root, nil); e != nil {
		t.Fatal("a missing entry is nil")
	}
	if rootDSE, _ := d.Get(ctx, "", []string{"supportedCapabilities"}); rootDSE == nil || len(rootDSE.Values("supportedCapabilities")) != 1 {
		t.Fatalf("root DSE: %v", rootDSE)
	}
	if err := d.Add(ctx, directory.Entry{DN: "CN=x," + root}); !errors.Is(err, directory.ErrReadOnly) {
		t.Fatalf("%v", err)
	}
	m := d.Meta()
	if m.Server != "ldaps://dc01:636" || m.MaskValue != "********" || strings.Join(m.Masked, ",") != "mail" || m.Entries != 10 {
		t.Fatalf("%+v", m)
	}
}

// A dump without its end line, or with another count, is refused: it was cut off.
func TestACutOffDumpIsRefused(t *testing.T) {
	if _, err := read(t, dump(10, false), false); err == nil || !strings.Contains(err.Error(), "cut off") {
		t.Fatalf("no end line: %v", err)
	}
	if _, err := read(t, dump(12, true), false); err == nil || !strings.Contains(err.Error(), "says 12 entries and holds 10") {
		t.Fatalf("another count: %v", err)
	}
	if _, err := read(t, "dn: CN=x\n", false); err == nil || !strings.Contains(err.Error(), "not a dump") {
		t.Fatalf("not a dump: %v", err)
	}
}

// A compressed dump is read through a temporary copy, which Close removes; nothing of the entries is kept between
// reads, so what is read is the file as it is.
func TestACompressedDumpIsReadThroughATemporaryCopy(t *testing.T) {
	d, err := read(t, dump(10, true), true)
	if err != nil {
		t.Fatal(err)
	}
	if d.temp == "" {
		t.Fatal("a temporary copy")
	}
	if info, err := os.Stat(d.temp); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("readable by its owner only: %v %v", info, err)
	}
	if e, err := d.Get(context.Background(), "CN=Bob\\2C Jr.,OU=IDM,"+root, []string{"department"}); err != nil || e == nil || strings.Join(e.Values("department"), "") != "Sales" {
		t.Fatalf("%v %v", e, err)
	}
	d.Close()
	if _, err := os.Stat(d.temp); !os.IsNotExist(err) {
		t.Fatalf("removed by Close: %v", err)
	}
}

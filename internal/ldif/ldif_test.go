package ldif

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

func TestLineEncodesUnsafeValues(t *testing.T) {
	cases := map[string]string{
		"plain":      "cn: plain",
		" lead":      "cn:: IGxlYWQ=",
		"日本語":        "cn:: " + "5pel5pys6Kqe",
		"trail ":     "cn:: dHJhaWwg",
		":colon":     "cn:: OmNvbG9u",
		"multi\nrow": "cn:: bXVsdGkKcm93",
	}
	for in, want := range cases {
		if got := Line("cn", in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestPasswordIsNeverPrinted(t *testing.T) {
	var b bytes.Buffer
	w := Writer{W: &b, Secret: []string{"unicodePwd", "userPassword"}}
	w.Replace("cn=a", map[string][]string{"unicodePwd": {"secret"}})
	w.Add("cn=b", map[string][]string{"cn": {"b"}, "USERPASSWORD": {"plain"}})
	if out := b.String(); strings.Contains(out, "secret") || strings.Contains(out, "plain") || !strings.Contains(out, "<redacted>") {
		t.Fatal(out)
	}
}

// ldapmodify sends a control line with the request; RFC 2849 puts it between dn and changetype.
func TestAddWritesControlsBeforeChangetype(t *testing.T) {
	var b bytes.Buffer
	Writer{W: &b}.Add("ou=x,dc=example", map[string][]string{"ou": {"x"}}, directory.Control{OID: "1.3.6.1.4.1.4203.666.5.12", Critical: true})
	want := "dn: ou=x,dc=example\ncontrol: 1.3.6.1.4.1.4203.666.5.12 true\nchangetype: add\nou: x\n\n"
	if b.String() != want {
		t.Fatalf("got\n%s", b.String())
	}
}

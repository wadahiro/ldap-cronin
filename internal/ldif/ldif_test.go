package ldif

import (
	"bytes"
	"strings"
	"testing"
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

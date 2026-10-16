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
	Replace(&b, "cn=a", map[string][]string{"unicodePwd": {"secret"}})
	if strings.Contains(b.String(), "secret") || !strings.Contains(b.String(), "<redacted>") {
		t.Fatal(b.String())
	}
}

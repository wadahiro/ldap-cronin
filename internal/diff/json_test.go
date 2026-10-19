package diff

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func decode(t *testing.T, d Difference) map[string]any {
	t.Helper()
	var b bytes.Buffer
	if err := NewJSON(&b).Difference(d); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatalf("%q: %v", b.String(), err)
	}
	return m
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestJSONCarriesEveryValueAndEveryKind(t *testing.T) {
	var many []string
	for i := range 25 {
		many = append(many, fmt.Sprintf("CN=u%02d,OU=Users,DC=x", i))
	}
	m := decode(t, Difference{Kind: Differ, DN: "CN=g,DC=x", Attr: "member", Multi: true, OnlySource: many})
	if got := strs(m["only_source"]); len(got) != 25 || got[24] != many[24] {
		t.Fatalf("values are never cut short: %v", got)
	}
	if got := m["only_target"].([]any); len(got) != 0 {
		t.Fatalf("an empty side is []: %v", m)
	}
	if _, ok := m["source"]; ok {
		t.Fatalf("a multi-valued difference has only_source/only_target: %v", m)
	}

	m = decode(t, Difference{Kind: Differ, DN: "CN=a,DC=x", Attr: "title", Target: []string{"<Lead> & co"}, CaseOnly: false})
	if len(m["source"].([]any)) != 0 || strs(m["target"])[0] != "<Lead> & co" {
		t.Fatalf("a value removed or added on one side, printed as it is: %v", m)
	}

	bin := string([]byte{0xff, 0x00, 0x10})
	m = decode(t, Difference{Kind: Differ, DN: "CN=a,DC=x", Attr: "jpegPhoto", Source: []string{bin}, Target: []string{"ok"}})
	if m["base64"] != true || strs(m["source"])[0] != base64.StdEncoding.EncodeToString([]byte(bin)) || strs(m["target"])[0] != "b2s=" {
		t.Fatalf("a value that is not UTF-8 makes the line base64: %v", m)
	}

	m = decode(t, Difference{Kind: Renamed, DN: "CN=a,DC=x", TargetDN: "CN=b,OU=y,DC=x", RDNRenamed: true, Moved: true})
	if m["target_dn"] != "CN=b,OU=y,DC=x" || m["renamed"] != true || m["moved"] != true {
		t.Fatalf("%v", m)
	}
	for _, k := range []Kind{OnlySource, OnlyTarget, Replaced, Unmarked} {
		if m := decode(t, Difference{Kind: k, DN: "CN=a,DC=x"}); m["kind"] != string(k) || m["dn"] != "CN=a,DC=x" || len(m) != 2 {
			t.Fatalf("%v", m)
		}
	}
}

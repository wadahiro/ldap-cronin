package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// diff -format json: every line is a JSON object a test program can read, the last one the summary, and the exit
// code is the text output's. Nothing else is on standard output.
func TestDiffWritesJSONLines(t *testing.T) {
	w := newWorld()
	s := w.open(t, ``)
	ctx := context.Background()
	if _, err := s.Clone(ctx, false, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	lines := func() (int, []map[string]any) {
		t.Helper()
		var out bytes.Buffer
		code, err := s.Diff(ctx, DiffOutput{JSON: true, MaxValues: 1}, &out)
		if err != nil {
			t.Fatal(err)
		}
		var got []map[string]any
		sc := bufio.NewScanner(&out)
		for sc.Scan() {
			var m map[string]any
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				t.Fatalf("not a JSON line: %q: %v", sc.Text(), err)
			}
			got = append(got, m)
		}
		return code, got
	}

	code, got := lines()
	if code != ExitSame || len(got) != 1 || got[0]["kind"] != "SUMMARY" || got[0]["version"] != float64(1) {
		t.Fatalf("a fresh clone: exit %d, %v", code, got)
	}

	w.dst.Lookup(alice).Attrs["title"] = []string{"Manager"}
	e := w.dst.Lookup(alice)
	w.dst.Delete(alice)
	e.Attrs["cn"] = []string{"Alice Renamed"}
	renamed := "CN=Alice Renamed,OU=Users," + base
	w.dst.Put(renamed, e.Attrs)
	code, got = lines()
	if code != ExitDiff {
		t.Fatalf("exit %d", code)
	}
	var kinds []string
	for _, m := range got {
		kinds = append(kinds, m["kind"].(string))
		switch m["kind"] {
		case "RENAMED":
			if m["dn"] != alice || m["target_dn"] != renamed || m["renamed"] != true {
				t.Errorf("%v", m)
			}
		case "DIFF":
			if m["attr"] != "title" || m["dn"] != renamed {
				t.Errorf("%v", m)
			}
		}
	}
	if strings.Join(kinds, ",") != "RENAMED,DIFF,SUMMARY" {
		t.Fatalf("%v", kinds)
	}
	sum := got[len(got)-1]
	if d := sum["differences"].(map[string]any); d["RENAMED"] != float64(1) || d["DIFF"] != float64(1) || d["ONLY_SOURCE"] != float64(0) {
		t.Fatalf("%v", sum)
	}
}

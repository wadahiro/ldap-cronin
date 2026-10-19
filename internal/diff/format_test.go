package diff

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/mask"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

func TestFormatSingleValued(t *testing.T) {
	var b bytes.Buffer
	Format(&b, Difference{Kind: Differ, DN: "CN=a,DC=x", Attr: "title", Source: []string{"Manager"}, Target: []string{"Changed"}}, DefaultMaxValues)
	want := "DIFF        CN=a,DC=x\n" +
		"            title:\n" +
		"              source: Manager\n" +
		"                      ~~~~~~~\n" +
		"              target: Changed\n" +
		"                      ~~~~~~~\n"
	if b.String() != want {
		t.Fatalf("got %q", b.String())
	}
}

func TestMarkersPointAtTheDifferingSpan(t *testing.T) {
	cases := []struct{ name, a, b, wantA, wantB string }{
		{"middle differs", "Sales Dept", "Sales Div", "       ~~~", "       ~~"},
		{"suffix differs", "user01@a.com", "user01@b.com", "       ~", "       ~"},
		{"insertion", "abc", "abXc", "  ^", "  ~"},
		{"deletion", "abXc", "abc", "  ~", "  ^"},
		{"japanese is double width", "営業部", "営業課", "    ~~", "    ~~"},
		{"case only", "Taro", "taro", "~", "~"},
	}
	for _, c := range cases {
		gotA, gotB := markers(c.a, c.b)
		if gotA != c.wantA || gotB != c.wantB {
			t.Errorf("%s: got %q / %q, want %q / %q", c.name, gotA, gotB, c.wantA, c.wantB)
		}
	}
}

func TestFormatSingleValuedShowsNoneForMissingSide(t *testing.T) {
	var b bytes.Buffer
	Format(&b, Difference{Kind: Differ, DN: "CN=a,DC=x", Attr: "title", Target: []string{"Hacked"}}, DefaultMaxValues)
	if !strings.Contains(b.String(), "source: (none)\n") || !strings.Contains(b.String(), "target: Hacked\n") || strings.Contains(b.String(), "~") {
		t.Fatal(b.String())
	}
}

func TestFormatMultiValuedListsValuesVertically(t *testing.T) {
	var b bytes.Buffer
	Format(&b, Difference{Kind: Differ, DN: "CN=g,DC=x", Attr: "member", Multi: true,
		OnlySource: []string{"CN=a", "CN=b"}, OnlyTarget: []string{"CN=z"}}, DefaultMaxValues)
	want := "DIFF        CN=g,DC=x\n" +
		"            member:\n" +
		"              only in source (2):\n" +
		"                - CN=a\n" +
		"                - CN=b\n" +
		"              only in target (1):\n" +
		"                - CN=z\n"
	if b.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", b.String(), want)
	}
}

func TestFormatMultiValuedHonorsMaxValues(t *testing.T) {
	var many []string
	for i := 0; i < 1600; i++ {
		many = append(many, fmt.Sprintf("CN=u%d", i))
	}
	d := Difference{Kind: Differ, DN: "CN=g", Attr: "member", Multi: true, OnlySource: many}

	var limited bytes.Buffer
	Format(&limited, d, 10)
	if strings.Count(limited.String(), "- CN=") != 10 || !strings.Contains(limited.String(), "(+1590 more") {
		t.Fatalf("limited output wrong:\n%s", limited.String())
	}
	var all bytes.Buffer
	Format(&all, d, 0)
	if strings.Count(all.String(), "- CN=") != 1600 || strings.Contains(all.String(), "more") {
		t.Fatal("max-values=0 must show every value")
	}
}

func TestWriteSummaryListsWhatIsNotCompared(t *testing.T) {
	opt := plan.Job{Profile: profile.AD, Masker: mask.New("***", []string{"mail"}), Kinds: []plan.Kind{
		{KindSpec: profile.KindSpec{Name: "ou"}, Attrs: []string{"objectClass", "ou"}},
		{KindSpec: profile.KindSpec{Name: "user"}, Attrs: []string{"objectClass", "mail", "title"}},
	}}
	var b bytes.Buffer
	WriteSummary(&b, opt, Summary{Compared: map[string]int{"ou": 3, "user": 5}, Differences: map[Kind]int{Differ: 2}}, []string{"telephoneNumber"})
	got := b.String()
	for _, want := range []string{
		"ou=3 user=5", "DIFF        : 2", "user : objectClass, title", // mail is masked, so it is excluded from the comparison
		"  masked (config [mask]):\n    mail\n", "  excluded (config exclude):\n    telephoneNumber\n",
		"  credentials (clone never copies them):\n    unicodePwd\n    dBCSPwd\n", "    ms-Mcs-AdmPwd\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestFormatCaseOnlySingleValueMarksEachDifferingCharacter(t *testing.T) {
	var b bytes.Buffer
	Format(&b, Difference{Kind: Differ, DN: "CN=a,DC=x", Attr: "mail", CaseOnly: true,
		Source: []string{"Alice@Example.com"}, Target: []string{"alice@example.com"}}, DefaultMaxValues)
	want := "DIFF        CN=a,DC=x\n" +
		"            mail:  (case only)\n" +
		"              source: Alice@Example.com\n" +
		"                      ~     ~\n" +
		"              target: alice@example.com\n" +
		"                      ~     ~\n"
	if b.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", b.String(), want)
	}
}

func TestCaseMarkersCountFullWidthLettersAsTwoColumns(t *testing.T) {
	a, b := caseMarkers("ＡBC", "ａBC") // full-width A and a
	if a != "~~" || b != "~~" {
		t.Fatalf("%q %q", a, b)
	}
}

func TestCasePairs(t *testing.T) {
	src, tgt, all := casePairs([]string{"SMTP:Alice@Example.com", "smtp:a.admin@example.com"}, []string{"SMTP:alice@example.com", "smtp:alice.admin@example.com"})
	if !src[0] || src[1] || !tgt[0] || tgt[1] || all {
		t.Fatalf("src=%v tgt=%v all=%v", src, tgt, all)
	}
	if _, _, all := casePairs([]string{"A", "B"}, []string{"a", "b"}); !all {
		t.Fatal("every value has a case-only partner: the whole difference is case only")
	}
	if _, _, all := casePairs([]string{"A"}, []string{"a", "extra"}); all {
		t.Fatal("an unmatched value means it is not a case-only difference")
	}
}

func TestFormatMultiValuedTagsCaseOnlyPairs(t *testing.T) {
	var b bytes.Buffer
	Format(&b, Difference{Kind: Differ, DN: "CN=a,DC=x", Attr: "proxyAddresses", Multi: true,
		OnlySource:     []string{"SMTP:Alice@Example.com", "smtp:a.admin@example.com"},
		OnlyTarget:     []string{"SMTP:alice@example.com", "smtp:alice.admin@example.com"},
		SourceCasePair: []bool{true, false}, TargetCasePair: []bool{true, false}}, DefaultMaxValues)
	want := "DIFF        CN=a,DC=x\n" +
		"            proxyAddresses:\n" +
		"              only in source (2):\n" +
		"                - SMTP:Alice@Example.com    (case only: same value on target side)\n" +
		"                - smtp:a.admin@example.com\n" +
		"              only in target (2):\n" +
		"                - SMTP:alice@example.com    (case only: same value on source side)\n" +
		"                - smtp:alice.admin@example.com\n"
	if b.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", b.String(), want)
	}
}

func TestWriteSummaryShowsCaseOnlyCountOnlyWhenPresent(t *testing.T) {
	opt := plan.Job{Profile: profile.AD, Masker: mask.New("***", nil), Kinds: []plan.Kind{
		{KindSpec: profile.KindSpec{Name: "user"}, Attrs: []string{"mail"}},
	}}
	var with, without bytes.Buffer
	WriteSummary(&with, opt, Summary{Compared: map[string]int{"user": 1}, Differences: map[Kind]int{Differ: 3}, CaseOnly: 2}, nil)
	WriteSummary(&without, opt, Summary{Compared: map[string]int{"user": 1}, Differences: map[Kind]int{Differ: 3}}, nil)
	if !strings.Contains(with.String(), "                    of which case only: 2\n") || strings.Contains(without.String(), "case only") {
		t.Fatalf("with:\n%s\nwithout:\n%s", with.String(), without.String())
	}
}

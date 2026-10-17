package main

import (
	"flag"
	"io"
	"reflect"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/lab"
)

func TestParseInterleavedAcceptsFlagsBeforeAndAfterThePositionalArgument(t *testing.T) {
	cases := [][]string{
		{"--note", "メモ", "baseline"},
		{"baseline", "--note", "メモ"},
		{"--force", "baseline", "--note", "メモ"},
	}
	for _, args := range cases {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		note := fs.String("note", "", "")
		force := fs.Bool("force", false, "")
		pos, err := parseInterleaved(fs, args)
		if err != nil || !reflect.DeepEqual(pos, []string{"baseline"}) || *note != "メモ" {
			t.Errorf("%v: pos=%v note=%q err=%v", args, pos, *note, err)
		}
		_ = force
	}
}

func TestParseInterleavedReturnsEveryPositionalArgument(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Bool("force", false, "")
	pos, err := parseInterleaved(fs, []string{"a", "--force", "b"})
	if err != nil || !reflect.DeepEqual(pos, []string{"a", "b"}) {
		t.Fatalf("%v %v", pos, err)
	}
}

func TestParseInterleavedRejectsUnknownFlags(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if _, err := parseInterleaved(fs, []string{"x", "--nope"}); err == nil {
		t.Fatal("unknown flag must fail")
	}
}

func TestMergeLikeLetsExplicitFlagsWin(t *testing.T) {
	base := lab.Settings{Domain: "src.example.com", NetBIOS: "SRC", DomainSID: "S-1-5-21-1-2-3", DomainGUID: "g"}
	got := mergeLike(base, lab.Settings{NetBIOS: "LAB", LDAPPort: 1, LDAPSPort: 2, AdminPassword: "pw"})
	if got.Domain != "src.example.com" || got.NetBIOS != "LAB" || got.DomainSID != "S-1-5-21-1-2-3" || got.LDAPPort != 1 || got.AdminPassword != "pw" {
		t.Fatalf("%+v", got)
	}
}

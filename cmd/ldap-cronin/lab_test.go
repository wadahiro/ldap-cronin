package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func TestMappingPathPrefersTheExplicitFileThenTheConfigsMappingFile(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfg, []byte(`
[mapping]
file = "from-config.tsv"
[source]
url = "ldaps://s:636"
bind_dn = "CN=a"
[target]
url = "ldaps://t:636"
bind_dn = "CN=a"
[scope]
base_dn = "OU=IDM,DC=x,DC=test"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var errw bytes.Buffer
	if got, err := mappingPath(cfg, "explicit.tsv", &errw); err != nil || got != "explicit.tsv" {
		t.Fatalf("%q %v", got, err)
	}
	if got, err := mappingPath(cfg, "", &errw); err != nil || got != "from-config.tsv" {
		t.Fatalf("%q %v", got, err)
	}
	if got, err := mappingPath("", "", &errw); err != nil || got != "" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := mappingPath(filepath.Join(t.TempDir(), "none.toml"), "", &errw); err == nil {
		t.Fatal("an unreadable --config must be an error")
	}
}

func TestMappingPathWarnsWhenTheConfigHasNoMappingFile(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfg, []byte(`
[source]
url = "ldaps://s:636"
bind_dn = "CN=a"
[target]
url = "ldaps://t:636"
bind_dn = "CN=a"
[scope]
base_dn = "OU=IDM,DC=x,DC=test"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var errw bytes.Buffer
	got, err := mappingPath(cfg, "", &errw)
	if err != nil || got != "" || !strings.Contains(errw.String(), "[mapping] file") {
		t.Fatalf("%q %v %q", got, err, errw.String())
	}
}

func TestMergeLikeLetsExplicitFlagsWin(t *testing.T) {
	base := lab.Settings{Realm: "src.example.com", NetBIOS: "SRC", DomainSID: "S-1-5-21-1-2-3", DomainGUID: "g"}
	got := mergeLike(base, lab.Settings{NetBIOS: "LAB", LDAPPort: 1, LDAPSPort: 2, AdminPassword: "pw"})
	if got.Realm != "src.example.com" || got.NetBIOS != "LAB" || got.DomainSID != "S-1-5-21-1-2-3" || got.LDAPPort != 1 || got.AdminPassword != "pw" {
		t.Fatalf("%+v", got)
	}
}

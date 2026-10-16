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

func TestGUIDMapPathPrefersTheExplicitFileThenTheConfigsStateFile(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfg, []byte(`
[state]
file = "from-config.tsv"
[source]
url = "ldaps://s:636"
bind_dn = "CN=a"
[target]
url = "ldaps://t:636"
bind_dn = "CN=a"
[clone]
base_dn = "OU=IDM,DC=x,DC=test"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var errw bytes.Buffer
	if got, err := guidMapPath(cfg, "explicit.tsv", &errw); err != nil || got != "explicit.tsv" {
		t.Fatalf("%q %v", got, err)
	}
	if got, err := guidMapPath(cfg, "", &errw); err != nil || got != "from-config.tsv" {
		t.Fatalf("%q %v", got, err)
	}
	if got, err := guidMapPath("", "", &errw); err != nil || got != "" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := guidMapPath(filepath.Join(t.TempDir(), "none.toml"), "", &errw); err == nil {
		t.Fatal("an unreadable --config must be an error")
	}
}

func TestGUIDMapPathWarnsWhenTheConfigHasNoStateFile(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfg, []byte(`
[source]
url = "ldaps://s:636"
bind_dn = "CN=a"
[target]
url = "ldaps://t:636"
bind_dn = "CN=a"
[clone]
base_dn = "OU=IDM,DC=x,DC=test"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var errw bytes.Buffer
	got, err := guidMapPath(cfg, "", &errw)
	if err != nil || got != "" || !strings.Contains(errw.String(), "[state] file") {
		t.Fatalf("%q %v %q", got, err, errw.String())
	}
}

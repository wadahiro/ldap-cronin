package main

import (
	"bytes"
	"flag"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/config"
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

// lab up --dry-run of an EC2 lab shows the user data and each aws command with why, and what goes on standard
// input described, never given.
func TestWriteEC2PlanShowsTheUserDataAndTheCommands(t *testing.T) {
	e := lab.EC2Lab{Name: "ldap-cronin-ad", Domain: "ad.example.com", NetBIOS: "AD", Region: "ap-northeast-1", Subnet: "subnet-0123",
		InstanceProfile: "p", PasswordParameter: "/ldap-cronin/ldap-cronin-ad/admin-password", LocalPort: 12636}
	var out bytes.Buffer
	if err := writeEC2Plan(&out, e); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"dry run: nothing is done on AWS", "==> The user data of the instance\n<powershell>", "</powershell>\n<persist>true</persist>\n",
		"\n# 2. the Administrator password", "\naws ssm put-parameter --region ap-northeast-1 --cli-input-json file:///dev/stdin\n",
		"#    standard input: {\"Name\": \"/ldap-cronin/ldap-cronin-ad/admin-password\", \"Type\": \"SecureString\"",
		"\n# 7. LDAPS of the instance at localhost:12636"} {
		if !strings.Contains(text, want) {
			t.Errorf("the plan lacks %q:\n%s", want, text)
		}
	}
}

// clone and check do not take an EC2 lab yet.
func TestLabOfRefusesAnEC2Lab(t *testing.T) {
	if _, err := labOf(&config.Lab{Platform: config.PlatformEC2}, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "--dry-run") {
		t.Fatalf("%v", err)
	}
}

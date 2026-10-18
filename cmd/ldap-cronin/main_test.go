package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

const (
	domain = "DC=ad,DC=example,DC=com"
	base   = "OU=IDM," + domain
	alice  = "CN=Alice,OU=Users," + base
)

type fakeConn struct{ *fakedir.Dir }

func (c fakeConn) View([]string) directory.Directory { return c.Dir }
func (c fakeConn) Close()                            {}

// cli replaces the dialer with in-memory directories and writes a config file, so run() is tested as a user runs it.
func cli(t *testing.T) (src, dst *fakedir.Dir, cfgPath string) {
	t.Helper()
	src = fakedir.New(domain)
	src.Put(domain, map[string][]string{"objectClass": {"domainDNS"}})
	src.Put(base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}})
	src.Put("OU=Users,"+base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Users"}})
	src.Put(alice, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {"Alice"},
		"sAMAccountName": {"alice"}, "title": {"Engineer"}, "userAccountControl": {"512"}})
	dst = fakedir.New()
	dst.IDPrefix = 0xd1
	dst.Put(domain, map[string][]string{"objectClass": {"domainDNS"}})

	saved := dial
	dial = func(_ context.Context, ep config.Endpoint, _ string, _ int) (app.Conn, error) {
		if strings.Contains(ep.URL, "src") {
			return fakeConn{src}, nil
		}
		return fakeConn{dst}, nil
	}
	t.Cleanup(func() { dial = saved })
	t.Setenv(envSourcePassword, "src-bind-pw")
	t.Setenv(envTargetPassword, "dst-bind-pw")
	t.Setenv(envUserPassword, "Fixed-Passw0rd!")

	cfgPath = filepath.Join(t.TempDir(), "config.toml")
	cfg := "[source]\nurl = \"ldaps://src:636\"\nbind_dn = \"CN=a\"\n[target]\nurl = \"ldaps://dst:636\"\nbind_dn = \"CN=a\"\n[scope]\nprofile = \"ad\"\nbase_dn = \"" + base + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return src, dst, cfgPath
}

func runCLI(t *testing.T, ctx context.Context, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(ctx, args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// clone, then diff: exit 0 without differences and 1 with one, as README promises scripts.
func TestCloneAndDiffExitCodes(t *testing.T) {
	_, dst, cfg := cli(t)
	ctx := context.Background()
	code, out, errOut := runCLI(t, ctx, "clone", "-config", cfg)
	if code != 0 || !strings.Contains(out, "added=") {
		t.Fatalf("clone: %d\n%s%s", code, out, errOut)
	}
	if got := dst.Lookup(alice).Values("unicodePwd"); len(got) != 1 || got[0] != profile.EncodePassword("Fixed-Passw0rd!") {
		t.Fatalf("the fixed password comes from %s: %q", envUserPassword, got)
	}
	if strings.Contains(out+errOut, "Fixed-Passw0rd!") || strings.Contains(out+errOut, "bind-pw") {
		t.Fatal("a password must never be printed")
	}
	if code, out, _ := runCLI(t, ctx, "diff", "-config", cfg); code != 0 || !strings.Contains(out, "no differences") {
		t.Fatalf("diff after clone: %d\n%s", code, out)
	}
	dst.Lookup(alice).Attrs["title"] = []string{"Manager"}
	if code, out, _ := runCLI(t, ctx, "diff", "-config", cfg); code != 1 || !strings.Contains(out, "DIFF") {
		t.Fatalf("diff with a change: %d\n%s", code, out)
	}
}

// A dry-run's standard output is only LDIF, so it can be piped into ldapmodify; nothing is written.
func TestDryRunStdoutIsOnlyLDIF(t *testing.T) {
	_, dst, cfg := cli(t)
	code, out, errOut := runCLI(t, context.Background(), "clone", "-dry-run", "-config", cfg)
	if code != 0 {
		t.Fatalf("%d\n%s", code, errOut)
	}
	if !strings.Contains(out, "dn: "+alice) {
		t.Fatalf("no LDIF:\n%s", out)
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" || line == "-" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, " ") || strings.Contains(line, ":") {
			continue
		}
		t.Errorf("not an LDIF line on stdout: %q", line)
	}
	if strings.Contains(out, "added=") || strings.Contains(out, "Fixed-Passw0rd!") {
		t.Fatalf("progress and passwords must stay off stdout:\n%s", out)
	}
	if dst.Lookup(alice) != nil {
		t.Fatal("a dry-run must not write")
	}
}

func TestErrorsExitWith2(t *testing.T) {
	_, _, cfg := cli(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, c := range map[string]struct {
		ctx  context.Context
		args []string
		want string
	}{
		"no command":       {context.Background(), nil, "Usage:"},
		"unknown command":  {context.Background(), []string{"klone"}, `unknown command "klone"`},
		"missing config":   {context.Background(), []string{"diff", "-config", filepath.Join(t.TempDir(), "none.toml")}, "error:"},
		"unknown flag":     {context.Background(), []string{"clone", "-bogus"}, "error:"},
		"native + dry-run": {context.Background(), []string{"clone", "-native", "-dry-run", "-config", cfg}, "cannot be used together"},
		"interrupted":      {cancelled, []string{"clone", "-config", cfg}, "interrupted"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, errOut := runCLI(t, c.ctx, c.args...)
			if code != exitError || !strings.Contains(errOut, c.want) {
				t.Fatalf("code %d, stderr %q (want %q)", code, errOut, c.want)
			}
		})
	}
}

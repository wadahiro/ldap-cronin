package app

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
)

const (
	domain = "DC=ad,DC=example,DC=com"
	base   = "OU=IDM," + domain
	alice  = "CN=Alice,OU=Users," + base
)

type fakeConn struct{ *fakedir.Dir }

func (c fakeConn) View([]string) directory.Directory { return c.Dir }
func (c fakeConn) Close()                            {}

// world is a source and a target behind a Dialer, with a record of what was dialed and which passwords were asked.
type world struct {
	src, dst *fakedir.Dir
	dialed   []string
	asked    []string
}

func newWorld() *world {
	src := fakedir.New(domain)
	src.Put(domain, map[string][]string{"objectClass": {"domainDNS"}})
	src.Put(base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}})
	src.Put("OU=Users,"+base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Users"}})
	src.Put(alice, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {"Alice"},
		"sAMAccountName": {"alice"}, "title": {"Engineer"}, "userAccountControl": {"512"}})
	dst := fakedir.New()
	dst.Put(domain, map[string][]string{"objectClass": {"domainDNS"}})
	return &world{src: src, dst: dst}
}

func (w *world) dial(_ context.Context, ep config.Endpoint, _ string, _ int) (Conn, error) {
	w.dialed = append(w.dialed, ep.URL)
	if strings.Contains(ep.URL, "src") {
		return fakeConn{w.src}, nil
	}
	return fakeConn{w.dst}, nil
}

func (w *world) secrets() Secrets {
	ask := func(name string) func() (string, error) {
		return func() (string, error) { w.asked = append(w.asked, name); return "pw-" + name, nil }
	}
	return Secrets{SourceBind: ask("source"), TargetBind: ask("target"), UserPassword: ask("user")}
}

// open opens a session; mapping is the body of the [mapping] section.
func (w *world) open(t *testing.T, mapping string) *Session {
	t.Helper()
	cfg, err := config.Parse([]byte(`
[source]
url = "ldaps://src:636"
bind_dn = "CN=a"
[target]
url = "ldaps://dst:636"
bind_dn = "CN=a"
[scope]
profile = "ad"
base_dn = "` + base + `"
[mapping]
` + mapping + `
`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), cfg, w.secrets(), w.dial, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestCloneThenDiffThroughTheSession(t *testing.T) {
	for name, mapping := range map[string]string{
		"marker (the default on AD)": ``,
		"file":                       `mode = "file"` + "\n" + `file = "` + filepath.Join(t.TempDir(), "mapping") + `"`,
	} {
		t.Run(name, func(t *testing.T) { cloneThenDiff(t, mapping) })
	}
}

func cloneThenDiff(t *testing.T, mapping string) {
	w := newWorld()
	s := w.open(t, mapping)
	ctx := context.Background()
	report, err := s.Clone(ctx, false, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil || report.Added == 0 {
		t.Fatalf("%+v %v", report, err)
	}
	if code, err := s.Diff(ctx, 10, &bytes.Buffer{}); err != nil || code != ExitSame {
		t.Fatalf("a fresh clone must have no differences: %d %v", code, err)
	}

	w.dst.Lookup(alice).Attrs["title"] = []string{"Manager"}
	renamed := "CN=Alice Renamed,OU=Users," + base
	e := w.dst.Lookup(alice)
	w.dst.Delete(alice)
	e.Attrs["cn"] = []string{"Alice Renamed"}
	w.dst.Put(renamed, e.Attrs)
	var out bytes.Buffer
	code, err := s.Diff(ctx, 10, &out)
	if err != nil || code != ExitDiff {
		t.Fatalf("%d %v\n%s", code, err, out.String())
	}
	if !strings.Contains(out.String(), "RENAMED") || !strings.Contains(out.String(), "title:") {
		t.Fatalf("what clone recorded must find the rename, and the change must show:\n%s", out.String())
	}
}

// A dry-run reads only the source: it never dials the target and never asks for its password or the users'.
func TestDryRunTouchesOnlyTheSource(t *testing.T) {
	w := newWorld()
	s := w.open(t, ``)
	var out bytes.Buffer
	if _, err := s.Clone(context.Background(), true, &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	// The marker is named after the source alone, so an LDIF loaded with ldapmodify carries it too.
	if !strings.Contains(out.String(), "adminDisplayName: ldap-cronin:") {
		t.Fatal(out.String())
	}
	if len(w.dialed) != 1 || !strings.Contains(w.dialed[0], "src") || strings.Join(w.asked, ",") != "source" {
		t.Fatalf("dialed %v, asked %v", w.dialed, w.asked)
	}
	if !strings.Contains(out.String(), "dn: "+alice) || strings.Contains(out.String(), "pw-") {
		t.Fatal(out.String())
	}
	if w.dst.Lookup(alice) != nil {
		t.Fatal("a dry-run must not write")
	}
}

// A cancelled run stops and says so; cmd turns that into "interrupted" instead of a generic error.
func TestCancelledCloneReportsTheCancellation(t *testing.T) {
	w := newWorld()
	s := w.open(t, ``)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Clone(ctx, false, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("want the cancellation, got %v", err)
	}
}

// A marker attribute the tool also copies would be overwritten by the source value, or compared: refused up front.
func TestAMarkerAttributeInTheAllowListIsRefused(t *testing.T) {
	cfg, err := config.Parse([]byte(`
[source]
url = "ldaps://src:636"
bind_dn = "CN=a"
[target]
url = "ldaps://dst:636"
bind_dn = "CN=a"
[scope]
profile = "ad"
base_dn = "` + base + `"
[mapping]
attribute = "info"
`))
	if err != nil {
		t.Fatal(err)
	}
	w := newWorld()
	if _, err := Open(context.Background(), cfg, w.secrets(), w.dial, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "info") {
		t.Fatalf("got %v", err)
	}
}

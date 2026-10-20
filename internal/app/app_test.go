package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/identity"
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
	// pool puts each dialed directory behind a pool of as many connections as the session asks for (see pooled).
	pool   bool
	dialed []string
	asked  []string
}

func newWorld() *world {
	src := fakedir.New(domain)
	src.Put(domain, map[string][]string{"objectClass": {"domainDNS"}})
	src.Put(base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}})
	src.Put("OU=Users,"+base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Users"}})
	src.Put(alice, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {"Alice"},
		"sAMAccountName": {"alice"}, "title": {"Engineer"}, "userAccountControl": {"512"}})
	dst := fakedir.New()
	// Another server assigns other identifiers; without this the two fakes would hand out the same ones and diff
	// would take the target for a native import.
	dst.IDPrefix = 0xd1
	dst.Put(domain, map[string][]string{"objectClass": {"domainDNS"}})
	return &world{src: src, dst: dst, pool: true}
}

func (w *world) dial(_ context.Context, ep config.Endpoint, _ string, conns int) (Conn, error) {
	w.dialed = append(w.dialed, ep.URL)
	d := w.dst
	if strings.Contains(ep.URL, "src") {
		d = w.src
	}
	if w.pool {
		return pooledConn{newPooled(d, conns)}, nil
	}
	return fakeConn{d}, nil
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
	return w.openWith(t, "[mapping]\n"+mapping)
}

// openWith opens a session with more sections after [scope].
func (w *world) openWith(t *testing.T, more string) *Session {
	t.Helper()
	s, err := w.tryOpen(more)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func (w *world) tryOpen(more string) (*Session, error) {
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
` + more + `
`))
	if err != nil {
		return nil, err
	}
	return Open(context.Background(), cfg, w.secrets(), w.dial, &bytes.Buffer{})
}

func TestCloneThenDiffThroughTheSession(t *testing.T) {
	for name, c := range map[string]struct{ mapping, check string }{
		"marker (the default on AD)": {``, "markers in adminDisplayName"},
		"file":                       {`mode = "file"` + "\n" + `file = "` + filepath.Join(t.TempDir(), "mapping") + `"`, "3 objectGUID pairs in the mapping file"},
	} {
		t.Run(name, func(t *testing.T) { cloneThenDiff(t, c.mapping, c.check) })
	}
}

// cloneThenDiff clones, diffs clean, then finds a rename through the carrier the summary names as check.
func cloneThenDiff(t *testing.T, mapping, check string) {
	w := newWorld()
	s := w.open(t, mapping)
	ctx := context.Background()
	report, err := s.Clone(ctx, false, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil || report.Added == 0 {
		t.Fatalf("%+v %v", report, err)
	}
	if code, err := s.Diff(ctx, DiffOutput{MaxValues: 10}, &bytes.Buffer{}); err != nil || code != ExitSame {
		t.Fatalf("a fresh clone must have no differences: %d %v", code, err)
	}

	w.dst.Lookup(alice).Attrs["title"] = []string{"Manager"}
	renamed := "CN=Alice Renamed,OU=Users," + base
	e := w.dst.Lookup(alice)
	w.dst.Delete(alice)
	e.Attrs["cn"] = []string{"Alice Renamed"}
	w.dst.Put(renamed, e.Attrs)
	var out bytes.Buffer
	code, err := s.Diff(ctx, DiffOutput{MaxValues: 10}, &out)
	if err != nil || code != ExitDiff {
		t.Fatalf("%d %v\n%s", code, err, out.String())
	}
	if !strings.Contains(out.String(), "rename/move check: on ("+check) {
		t.Fatalf("the rename must be found through %s:\n%s", check, out.String())
	}
	if !strings.Contains(out.String(), "RENAMED") || !strings.Contains(out.String(), "title:") {
		t.Fatalf("what clone recorded must find the rename, and the change must show:\n%s", out.String())
	}
}

// A rename alone is a difference: exit 1, as without detection (ONLY_SOURCE + ONLY_TARGET), never "no differences".
func TestARenameAloneMakesDiffExitWith1(t *testing.T) {
	w := newWorld()
	s := w.open(t, ``)
	ctx := context.Background()
	if _, err := s.Clone(ctx, false, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	e := w.dst.Lookup(alice)
	w.dst.Delete(alice)
	e.Attrs["cn"] = []string{"Alice Renamed"}
	w.dst.Put("CN=Alice Renamed,OU=Users,"+base, e.Attrs)
	var out bytes.Buffer
	code, err := s.Diff(ctx, DiffOutput{MaxValues: 10}, &out)
	if err != nil || code != ExitDiff || strings.Contains(out.String(), "no differences") || !strings.Contains(out.String(), "RENAMED") {
		t.Fatalf("%d %v\n%s", code, err, out.String())
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

// One mapping file serves every target cloned from one source (a lab recreated from scratch, another instance):
// clone into another target with the same file succeeds, and both targets diff clean.
func TestOneMappingFileServesASecondTarget(t *testing.T) {
	mapping := `mode = "file"` + "\n" + `file = "` + filepath.Join(t.TempDir(), "mapping") + `"`
	first, second := newWorld(), newWorld()
	second.src = first.src
	second.dst.IDPrefix = 0xd2
	ctx := context.Background()
	for _, w := range []*world{first, second} {
		if _, err := w.open(t, mapping).Clone(ctx, false, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatalf("clone: %v", err)
		}
	}
	for i, w := range []*world{first, second} {
		var out bytes.Buffer
		if code, err := w.open(t, mapping).Diff(ctx, DiffOutput{MaxValues: 10}, &out); err != nil || code != ExitSame {
			t.Fatalf("target %d: %d %v\n%s", i+1, code, err, out.String())
		}
	}
}

// A mapping file that is missing or belongs to another source turns rename detection off with a note saying why,
// instead of failing diff or matching wrongly.
func TestDiffWithAnUnusableMappingFileSaysWhy(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		prepare func(path string)
		note    string
	}{
		"missing": {func(path string) { os.Remove(path) }, "not found"},
		"another source": {func(path string) {
			os.Remove(path)
			m, err := identity.Open(path, identity.Header{Scheme: identity.ObjectGUID.Attr(), SourceRoot: identity.Key{9}})
			if err != nil {
				t.Fatal(err)
			}
			m.Close()
		}, "belongs to another source"},
		"old format": {func(path string) {
			os.WriteFile(path, []byte("# ldap-cronin mapping v4 scheme=objectGUID source-root=aa target-root=bb base_dn=x\n"), 0o600)
		}, "another format"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mapping")
			mapping := `mode = "file"` + "\n" + `file = "` + path + `"`
			w := newWorld()
			if _, err := w.open(t, mapping).Clone(ctx, false, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			c.prepare(path)
			e := w.dst.Lookup(alice)
			w.dst.Delete(alice)
			e.Attrs["cn"] = []string{"Alice Renamed"}
			w.dst.Put("CN=Alice Renamed,OU=Users,"+base, e.Attrs)

			s := w.open(t, mapping)
			var warn, out bytes.Buffer
			s.Warn = &warn
			code, err := s.Diff(ctx, DiffOutput{MaxValues: 10}, &out)
			if err != nil || code != ExitDiff {
				t.Fatalf("%d %v", code, err)
			}
			if !strings.Contains(warn.String(), c.note) || !strings.Contains(warn.String(), "rename/move detection is off") {
				t.Errorf("the note must say why detection is off: %q", warn.String())
			}
			if strings.Contains(out.String(), "RENAMED") || !strings.Contains(out.String(), "ONLY_SOURCE") || !strings.Contains(out.String(), "ONLY_TARGET") {
				t.Errorf("without the mapping a rename is a missing and an extra entry:\n%s", out.String())
			}
		})
	}
}

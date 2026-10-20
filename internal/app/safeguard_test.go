package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/lab"
)

// Every write to the source is refused before it reaches the server, through the session's view and its connection.
func TestTheSourceIsReadOnly(t *testing.T) {
	w := newWorld()
	s := w.open(t, "")
	ctx := context.Background()
	for _, d := range []directory.Directory{s.Src, s.src} {
		for name, err := range map[string]error{
			"add":     d.Add(ctx, directory.Entry{DN: "CN=Bob,OU=Users," + base, Attrs: map[string][]string{"cn": {"Bob"}}}),
			"replace": d.Replace(ctx, alice, map[string][]string{"title": {"Manager"}}),
			"values":  d.AddValues(ctx, alice, "description", []string{"x"}),
		} {
			if !errors.Is(err, directory.ErrReadOnly) {
				t.Errorf("%s on the source: %v, want ErrReadOnly", name, err)
			}
		}
	}
	if got := w.src.Lookup(alice).Values("title"); len(got) != 1 || got[0] != "Engineer" {
		t.Fatalf("the source was written: title %q", got)
	}
	if w.src.Lookup("CN=Bob,OU=Users,"+base) != nil || len(w.src.Lookup(alice).Values("description")) != 0 {
		t.Fatal("the source was written")
	}
}

// With Confirm set, clone shows the target (with the name its root DSE gives) and the source, and a no writes nothing.
func TestCloneAsksBeforeWritingTheTarget(t *testing.T) {
	w := newWorld()
	w.dst.Put("", map[string][]string{"dnsHostName": {"dc1.test.example.com"}})
	s := w.open(t, "")
	var shown bytes.Buffer
	s.Warn = &shown
	var asked string
	s.Confirm = func(q string) bool { asked = q; return false }
	before := len(w.dst.Entries)
	if _, err := s.Clone(context.Background(), false, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("a no must stop the clone: %v", err)
	}
	if len(w.dst.Entries) != before {
		t.Fatalf("a no wrote to the target: %d entries, had %d", len(w.dst.Entries), before)
	}
	for _, want := range []string{"target (written): ldaps://dst:636 (server dc1.test.example.com)", "base_dn: " + base, "source (read only): ldaps://src:636"} {
		if !strings.Contains(shown.String(), want) {
			t.Errorf("the question does not show %q:\n%s", want, shown.String())
		}
	}
	if !strings.Contains(asked, "[y/N]") {
		t.Errorf("the question must say No is the default: %q", asked)
	}

	s.Confirm = func(string) bool { return true }
	if report, err := s.Clone(context.Background(), false, &bytes.Buffer{}, &bytes.Buffer{}); err != nil || report.Added == 0 {
		t.Fatalf("a yes clones: %+v %v", report, err)
	}
}

// clone -native asks too, naming the lab, before it stops the lab: a no leaves it running and untouched.
func TestNativeAsksBeforeStoppingTheLab(t *testing.T) {
	w := newWorld()
	w.src.Put(domain, map[string][]string{"objectGUID": {"0123456789abcdef"}, "objectSid": {"\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00"}})
	s := w.open(t, "")
	var shown bytes.Buffer
	s.Warn = &shown
	asked := false
	s.Confirm = func(string) bool { asked = true; return false }
	_, err := s.Native(context.Background(), &lab.Lab{Prefix: "t"}, lab.NativeOptions{}, &bytes.Buffer{})
	if !asked || err == nil || !strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("a no must stop before the lab is touched: asked=%v %v", asked, err)
	}
	if !strings.Contains(shown.String(), "target (written): the lab t-ad") {
		t.Errorf("the question must name the lab:\n%s", shown.String())
	}
}

// A dry-run writes nowhere, so it does not ask.
func TestDryRunDoesNotAsk(t *testing.T) {
	s := newWorld().open(t, "")
	s.Confirm = func(string) bool { t.Fatal("a dry-run asked"); return false }
	if _, err := s.Clone(context.Background(), true, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}

// A Samba target refuses userParameters over LDAP: it is left out with the reason, in any mode, instead of stopping
// the run at the first user holding one. A Windows target (no vendorName) is given it.
func TestUserParametersIsLeftOutForASambaTarget(t *testing.T) {
	for name, c := range map[string]struct {
		vendor []string
		copied bool
	}{
		"Samba":   {[]string{"Samba Team (https://www.samba.org)"}, false},
		"Windows": {nil, true},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld()
			if c.vendor != nil {
				w.dst.Put("", map[string][]string{"vendorName": c.vendor})
			}
			w.src.Lookup(alice).Attrs["userParameters"] = []string{"P\x00CtxCfgPresent"}
			s := w.openWith(t, "[attributes]\nextra_include = [\"userParameters\"]\n")
			ctx := context.Background()
			var log bytes.Buffer
			if _, err := s.Clone(ctx, false, &bytes.Buffer{}, &log); err != nil {
				t.Fatal(err)
			}
			got := w.dst.Lookup(alice)
			if (got.Values("userParameters") != nil) != c.copied || strings.Join(got.Values("title"), "") != "Engineer" {
				t.Fatalf("copied %v, want %v: %v", got.Values("userParameters") != nil, c.copied, got.Attrs)
			}
			noted := strings.Contains(log.String(), "the target refuses 1 attributes over LDAP") && strings.Contains(log.String(), "userParameters: Samba refuses it")
			if noted == c.copied {
				t.Fatalf("the note says why it is left out (and only then):\n%s", log.String())
			}
			var warn bytes.Buffer
			s.Warn = &warn
			if code, err := s.Diff(ctx, DiffOutput{}, &bytes.Buffer{}); err != nil || code != ExitSame {
				t.Fatalf("diff: %d %v", code, err)
			}
			var attrs bytes.Buffer
			if err := s.ListAttrs(ctx, true, &attrs); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(attrs.String(), "left out for this target: Samba refuses it") == c.copied {
				t.Fatalf("list-attrs -target:\n%s", attrs.String())
			}
		})
	}
}

// clone -native imports the domain partition only, so it refuses configuration_refs = "clone" before touching the lab.
func TestNativeRefusesConfigurationRefs(t *testing.T) {
	s := newWorld().open(t, "")
	s.Job.ConfigurationRefs = "clone"
	if _, err := s.Native(context.Background(), nil, lab.NativeOptions{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "not supported by clone -native") {
		t.Fatalf("%v", err)
	}
}

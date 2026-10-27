package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dump"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
	"github.com/wadahiro/ldap-cronin/internal/ldifdir"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// redumpWorld is a world whose source has display names under the base DN and outside it (a manager), a group
// outside the base DN holding a user of it, and a member the source does not return; firstDump is its dump with
// mail masked, taken at a fixed time.
// longName is a display name an LDIF writer encodes in base64 and may fold over several lines.
var longName = strings.Repeat("情報システム部 第一開発グループ アリス・エグザンプル ", 4)

func redumpWorld(t *testing.T) (w *world, firstDump string) {
	t.Helper()
	w = newWorld()
	person := "CN=Person,CN=Schema,CN=Configuration," + domain
	user := []string{"top", "person", "organizationalPerson", "user"}
	w.src.Lookup(domain).Attrs["objectGUID"] = []string{"0123456789abcdef"}
	w.src.Put("OU=Elsewhere,"+domain, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Elsewhere"}})
	boss := "CN=Boss,OU=Elsewhere," + domain
	w.src.Put(boss, map[string][]string{"objectClass": user, "cn": {"Boss"}, "sAMAccountName": {"boss"}, "userAccountControl": {"512"},
		"displayName": {"Boss Person"}, "objectCategory": {person}})
	w.src.Put("CN=Outside,OU=Elsewhere,"+domain, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Outside"},
		"sAMAccountName": {"outside"}, "member": {alice}})
	a := w.src.Lookup(alice).Attrs
	a["objectCategory"] = []string{person}
	// Long and not ASCII: written base64-encoded, past the width an LDIF tool folds at.
	a["displayName"] = []string{longName}
	a["mail"] = []string{"alice@example.com"}
	a["manager"] = []string{boss}
	a["memberOf"] = []string{"CN=Outside,OU=Elsewhere," + domain}
	w.src.Put("CN=Team,OU=Users,"+base, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Team"}, "sAMAccountName": {"team"},
		"displayName": {"The Team"}, "member": {alice, "CN=Gone,OU=Elsewhere," + domain}})
	var out bytes.Buffer
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	if _, err := dump.Write(context.Background(), w.src, profile.AD, dump.Options{BaseDNs: []string{base}, MaskValue: "********", Masked: []string{"mail"},
		Server: "ldaps://src:636", Version: "test", Now: func() time.Time { return at }}, &out); err != nil {
		t.Fatal(err)
	}
	firstDump = filepath.Join(t.TempDir(), "prod.ldif")
	if err := os.WriteFile(firstDump, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return w, firstDump
}

func redumpFile(t *testing.T, from, out string, masked ...string) dump.Counts {
	t.Helper()
	c, err := Dump(context.Background(), DumpOptions{From: from, Out: out, MaskValue: "********", Masked: masked, Version: "test"},
		func() (string, error) { t.Fatal("a dump of a dump asks for no password"); return "", nil }, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// entries is every entry of a dump, its attributes sorted, one line each.
func entries(t *testing.T, path string) (ldifdir.Meta, string) {
	t.Helper()
	d, err := ldifdir.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var lines []string
	for _, nc := range []string{domain} {
		_ = d.Walk(context.Background(), nc, "(objectClass=*)", []string{directory.AllAttrs, "memberOf"}, func(e directory.Entry) error {
			lines = append(lines, line(e))
			return nil
		})
	}
	sort.Strings(lines)
	return d.Meta(), strings.Join(lines, "\n")
}

func line(e directory.Entry) string {
	var attrs []string
	for n, v := range e.Attrs {
		sorted := append([]string(nil), v...)
		sort.Strings(sorted)
		attrs = append(attrs, strings.ToLower(n)+"="+strings.Join(sorted, "|"))
	}
	sort.Strings(attrs)
	return strings.ToLower(e.DN) + " " + strings.Join(attrs, " ")
}

// A dump of a dump with nothing more masked is the same dump: the same entries (the referenced ones, the groups
// holding entries of the base DN), the same entries the source did not return, and the same moment of the same
// server.
func TestADumpOfADumpIsTheSameDump(t *testing.T) {
	_, first := redumpWorld(t)
	second := filepath.Join(t.TempDir(), "again.ldif.gz")
	c := redumpFile(t, first, second)
	m1, e1 := entries(t, first)
	m2, e2 := entries(t, second)
	if e1 != e2 {
		t.Fatalf("the entries differ:\n%s\n\nagain:\n%s", e1, e2)
	}
	if c.Unreadable != 1 || c.Referenced == 0 || m1.Entries != m2.Entries {
		t.Fatalf("counts %+v, entries %d and %d", c, m1.Entries, m2.Entries)
	}
	if m2.DumpedAt != m1.DumpedAt || m2.Server != m1.Server || strings.Join(m2.Masked, ",") != "mail" || !m2.Holders {
		t.Fatalf("header: %+v", m2)
	}
}

// displayName masked in a dump of a dump: on every entry, the ones outside the base DN included, besides what the
// first dump masked; and a clone from the new dump into the target cloned from the first writes that alone, after
// which diff against the new dump finds nothing.
func TestADumpOfADumpMasksMoreAndAReCloneWritesThatAlone(t *testing.T) {
	ctx := context.Background()
	w, first := redumpWorld(t)
	second := filepath.Join(t.TempDir(), "masked.ldif")
	redumpFile(t, first, second, "displayName")
	m, all := entries(t, second)
	raw, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(all, longName) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte(longName))[:40])) || strings.Contains(all, "Boss Person") || strings.Contains(all, "The Team") ||
		!strings.Contains(all, "displayname=********") || strings.Join(m.Masked, ",") != "displayName,mail" {
		t.Fatalf("masked: %v\n%s", m.Masked, all)
	}

	open := func(path string) *Session {
		cfg, err := config.Parse([]byte("[source]\nldif = \"" + path + "\"\n[target]\nurl = \"ldaps://dst:636\"\nbind_dn = \"CN=a\"\n" +
			"[scope]\nprofile = \"ad\"\nbase_dn = \"" + base + "\"\n"))
		if err != nil {
			t.Fatal(err)
		}
		s, err := Open(ctx, cfg, w.secrets(), w.dial, &bytes.Buffer{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	var log bytes.Buffer
	if _, err := open(first).Clone(ctx, false, &log, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	before := targetWithout(w.dst, "displayName")
	s := open(second)
	log.Reset()
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	// Alice, the team, and Boss (created outside the base DN as the manager it names)
	if rep.Added != 0 || rep.Updated != 3 {
		t.Fatalf("the re-clone: %+v\n%s", rep, log.String())
	}
	if after := targetWithout(w.dst, "displayName"); after != before {
		t.Fatalf("more than displayName changed:\n%s\n\nafter:\n%s", before, after)
	}
	if got := w.dst.Lookup(alice).Values("displayName"); strings.Join(got, "") != "********" {
		t.Fatalf("alice's displayName: %v", got)
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitSame {
		t.Fatalf("diff against the new dump: %d %v\n%s", code, err, out.String())
	}
}

// targetWithout is the target's entries without the attributes named.
func targetWithout(d *fakedir.Dir, skip ...string) string {
	var lines []string
	for _, e := range d.Entries {
		c := directory.Entry{DN: e.DN, Attrs: map[string][]string{}}
		for n, v := range e.Attrs {
			if !containsFold(skip, n) {
				c.Attrs[n] = v
			}
		}
		lines = append(lines, line(c))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// A dump of a dump refuses what would make it say what it is not: a server besides the dump, a base DN the dump
// lacks, another mask value, credentials the dump does not carry, and writing over the dump it reads.
func TestADumpOfADumpRefusesWhatItCannotBe(t *testing.T) {
	_, first := redumpWorld(t)
	out := filepath.Join(t.TempDir(), "new.ldif")
	for name, c := range map[string]struct {
		o    DumpOptions
		want string
	}{
		"a server too":      {DumpOptions{Conn: ldapdir.ConnConfig{URL: "ldaps://src:636"}}, "no -url or -bind-dn"},
		"another base DN":   {DumpOptions{BaseDNs: []string{"OU=Elsewhere," + domain}}, "is not in"},
		"another value":     {DumpOptions{MaskValue: "xxx"}, `masks with "********"`},
		"credentials":       {DumpOptions{Credentials: true}, "carries no credentials"},
		"over its own dump": {DumpOptions{Out: first}, "is the dump -from reads"},
	} {
		t.Run(name, func(t *testing.T) {
			o := c.o
			o.From = first
			if o.Out == "" {
				o.Out = out
			}
			if o.MaskValue == "" {
				o.MaskValue = "********"
			}
			_, err := Dump(context.Background(), o, func() (string, error) { return "", nil }, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			if _, serr := os.Stat(out); serr == nil {
				t.Fatal("a refused dump wrote a file")
			}
		})
	}
}

// kind:attribute masks it on that kind's entries only, as dump -mask does: a user's displayName (the one outside the
// base DN too), not a group's.
func TestADumpOfADumpMasksOnAKind(t *testing.T) {
	_, first := redumpWorld(t)
	second := filepath.Join(t.TempDir(), "users.ldif")
	redumpFile(t, first, second, "user:displayName")
	m, all := entries(t, second)
	if strings.Contains(all, longName) || strings.Contains(all, "Boss Person") || !strings.Contains(all, "displayname=The Team") ||
		strings.Join(m.Masked, ",") != "mail,user:displayName" {
		t.Fatalf("masked %v:\n%s", m.Masked, all)
	}
}

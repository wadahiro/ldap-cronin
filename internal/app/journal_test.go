package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/dump"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// journalWorld is a world whose source is a dump of five users, and whose target says which it is and how many
// writes it has had, as an AD's domain root and root DSE do. The session is opened from a config file in a
// directory of its own, beside which the journal is kept.
func journalWorld(t *testing.T) (*world, *Session, string) {
	t.Helper()
	w := newWorld()
	user := []string{"top", "person", "organizationalPerson", "user"}
	// Every AD object has its objectCategory, which the dump's filters evaluate as AD does.
	person := "CN=Person,CN=Schema,CN=Configuration," + domain
	w.src.Lookup(domain).Attrs["objectGUID"] = []string{"0123456789abcdef"}
	w.src.Lookup(alice).Attrs["objectCategory"] = []string{person}
	for i := range 4 {
		w.src.Put(fmt.Sprintf("CN=User %d,OU=Users,%s", i, base), map[string][]string{"objectClass": user, "cn": {fmt.Sprintf("User %d", i)},
			"sAMAccountName": {fmt.Sprintf("user%d", i)}, "userAccountControl": {"512"}, "objectCategory": {person}})
	}
	var out bytes.Buffer
	if _, err := dump.Write(context.Background(), w.src, profile.AD, dump.Options{BaseDNs: []string{base}, Server: "ldaps://src:636", Version: "test"}, &out); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	dumpPath, cfgPath := filepath.Join(dir, "prod.ldif"), filepath.Join(dir, "lab.toml")
	if err := os.WriteFile(dumpPath, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	w.dst.Lookup(domain).Attrs["objectGUID"] = []string{"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"}
	w.dst.Put("", map[string][]string{"highestCommittedUSN": {"1000"}})
	cfg, err := config.Parse([]byte("[source]\nldif = \"" + dumpPath + "\"\n[target]\nurl = \"ldaps://dst:636\"\nbind_dn = \"CN=a\"\n" +
		"[scope]\nprofile = \"ad\"\nbase_dn = \"" + base + "\"\n[run]\nworkers = 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), cfg, w.secrets(), w.dial, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.ConfigPath = cfgPath
	return w, s, cfgPath + ".journal"
}

// stopAfterAdds cancels the run once the log says it added left users.
type stopAfterAdds struct {
	left int
	stop context.CancelFunc
	log  bytes.Buffer
}

func (w *stopAfterAdds) Write(p []byte) (int, error) {
	w.log.Write(p)
	if w.left > 0 && bytes.Contains(p, []byte("add    CN=User")) {
		if w.left--; w.left == 0 {
			w.stop()
		}
	}
	return len(p), nil
}

// interrupted runs a clone stopped after two users, which leaves the journal.
func interrupted(t *testing.T, s *Session, journal string) {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	log := &stopAfterAdds{left: 2, stop: stop}
	if _, err := s.Clone(ctx, false, log, log); !errors.Is(err, context.Canceled) {
		t.Fatalf("the interrupted clone: %v\n%s", err, log.log.String())
	}
	if _, err := os.Stat(journal); err != nil {
		t.Fatalf("the interrupted clone left no journal: %v\n%s", err, log.log.String())
	}
}

// A clone over LDAP from a dump that stops midway keeps what it finished in a journal beside the config file: the
// next run skips it, adds the rest, diffs clean and removes the journal; the one after compares everything again.
func TestAnInterruptedCloneGoesOnFromItsJournal(t *testing.T) {
	ctx := context.Background()
	w, s, journal := journalWorld(t)
	interrupted(t, s, journal)
	w.dst.Put("", map[string][]string{"highestCommittedUSN": {"1200"}}) // written since: a later point of the same target

	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if rep.Resumed < 1 || rep.Added == 0 || !strings.Contains(log.String(), "resuming: the journal "+journal+" holds") {
		t.Fatalf("the resumed clone: %+v\n%s", rep, log.String())
	}
	if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a complete clone keeps its journal: %v", err)
	}
	if code, err := s.Diff(ctx, DiffOutput{}, &bytes.Buffer{}); err != nil || code != ExitSame {
		t.Fatalf("diff after the resumed clone: %d %v", code, err)
	}
	log.Reset()
	if rep, err := s.Clone(ctx, false, &log, &log); err != nil || rep.Resumed != 0 || strings.Contains(log.String(), "resuming") {
		t.Fatalf("the clone after a complete one: %v %+v\n%s", err, rep, log.String())
	}
}

// A journal is dropped, and every object compared, when the target is not the one it was kept for: restored to an
// earlier point (fewer writes than the journal recorded), made anew (another domain identifier), or cloned with
// another config.
func TestAJournalOfAnotherTargetOrConfigIsDropped(t *testing.T) {
	for name, change := range map[string]func(w *world, s *Session){
		"restored to an earlier point": func(w *world, _ *Session) {
			w.dst.Put("", map[string][]string{"highestCommittedUSN": {"900"}})
		},
		"made anew": func(w *world, _ *Session) {
			w.dst.Lookup(domain).Attrs["objectGUID"] = []string{"\x10\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01"}
		},
		"another config": func(_ *world, s *Session) {
			s.Cfg.Attributes.Exclude = append(s.Cfg.Attributes.Exclude, "title")
		},
	} {
		t.Run(name, func(t *testing.T) {
			w, s, journal := journalWorld(t)
			interrupted(t, s, journal)
			change(w, s)
			var log bytes.Buffer
			rep, err := s.Clone(context.Background(), false, &log, &log)
			if err != nil {
				t.Fatalf("%v\n%s", err, log.String())
			}
			if rep.Resumed != 0 || !strings.Contains(log.String(), "note: the journal "+journal+" was of another dump, config or target") {
				t.Fatalf("%+v\n%s", rep, log.String())
			}
		})
	}
}

// The workers and where the journal is kept are not what it is valid for: a run after one stopped by a busy server
// may take fewer workers and go on.
func TestAJournalOutlivesAnotherNumberOfWorkers(t *testing.T) {
	_, s, journal := journalWorld(t)
	interrupted(t, s, journal)
	s.Cfg.Run.Workers = 4
	var log bytes.Buffer
	if rep, err := s.Clone(context.Background(), false, &log, &log); err != nil || rep.Resumed < 1 {
		t.Fatalf("%v %+v\n%s", err, rep, log.String())
	}
}

// Workers mark keys at once; a line cut off by a run that ended mid-write loses that key alone.
func TestAJournalTakesKeysFromEveryWorker(t *testing.T) {
	ctx := context.Background()
	w := newWorld()
	w.dst.Lookup(domain).Attrs["objectGUID"] = []string{"guid"}
	w.dst.Put("", map[string][]string{"highestCommittedUSN": {"7"}})
	path := filepath.Join(t.TempDir(), "j")
	load := func() *fileJournal {
		j, err := loadJournal(path, "fp", "id", 7, profile.AD.Generation, w.dst, domain)
		if err != nil || j.Stale {
			t.Fatalf("%v %+v", err, j)
		}
		return j
	}
	j := load()
	if err := j.start(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for k := range journalBatch {
				if err := j.Mark(ctx, fmt.Sprintf("object %d-%d", i, k)); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	if err := j.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`"object cut`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if got := load(); got.Len() != 8*journalBatch || !got.Has("object 7-499") || got.Has("object cut") {
		t.Fatalf("read back %d keys", got.Len())
	}
}

// Whether a native import ends with dbcheck does not change what it writes: the last slice of an import may skip a
// dbcheck that would take too long and keep the journal of the slices before it. What is written does change it.
func TestAJournalOutlivesSkippingDBCheck(t *testing.T) {
	_, s, _ := journalWorld(t)
	s.Cfg.Target.Lab = &config.Lab{Native: true}
	checked, _ := s.journalFingerprint()
	s.Cfg.Target.Lab = &config.Lab{Native: true, DBCheck: config.DBCheckSkip}
	skipped, _ := s.journalFingerprint()
	s.Cfg.Target.Lab = &config.Lab{Native: true, FastPassword: true}
	other, _ := s.journalFingerprint()
	if checked != skipped || checked == other || s.Cfg.Target.Lab.FastPassword != true {
		t.Fatalf("checked %s, skipped %s, fast_password %s", checked, skipped, other)
	}
}

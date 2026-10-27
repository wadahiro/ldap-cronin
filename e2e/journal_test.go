//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
)

// A clone over LDAP from a dump that is interrupted keeps what it finished in a journal beside the config file,
// guarded by the Samba target's domain GUID and highestCommittedUSN: the next run skips it, adds the rest, diffs
// clean and removes the journal.
func TestAnInterruptedCloneOverLDAPGoesOnFromItsJournal(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	ctx := context.Background()
	src := dial(t, srcURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	scope := fmt.Sprintf("OU=Journal%06d,%s", runID, realmDN)
	must(src.Add(ctx, directory.Entry{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("Journal%06d", runID)}}}))
	for i := range 6 {
		must(src.Add(ctx, directory.Entry{DN: fmt.Sprintf("CN=j%d,%s", i, scope), Attrs: map[string][]string{"objectClass": {"user"},
			"sAMAccountName": {fmt.Sprintf("j%06du%d", runID, i)}}}))
	}
	dir := t.TempDir()
	path, cfgPath := filepath.Join(dir, "prod.ldif.gz"), filepath.Join(dir, "lab.toml")
	journal := cfgPath + ".journal"
	pw := func() (string, error) { return adminPw, nil }
	_, err := app.Dump(ctx, app.DumpOptions{Conn: ldapdir.ConnConfig{URL: srcURL, BindDN: adminDN, InsecureSkipVerify: true},
		BaseDNs: []string{scope}, Out: path, Version: "e2e"}, pw, &bytes.Buffer{})
	must(err)
	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nldif = %q\n[target]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n"+
		"[scope]\nbase_dn = %q\n[run]\nworkers = 1\n", path, dstURL, adminDN, scope)))
	must(err)
	s, err := app.Open(ctx, cfg, app.Secrets{TargetBind: pw, UserPassword: func() (string, error) { return fixedPw, nil }}, app.LDAP, &bytes.Buffer{})
	must(err)
	t.Cleanup(s.Close)
	s.ConfigPath = cfgPath

	stopped, stop := context.WithCancel(ctx)
	interrupt := &stopAfterUsers{left: 3, prefix: "add    CN=j", stop: stop}
	if _, err := s.Clone(stopped, false, interrupt, interrupt); !errors.Is(err, context.Canceled) {
		t.Fatalf("the interrupted clone: %v\n%s", err, interrupt.log.String())
	}
	if _, err := os.Stat(journal); err != nil {
		t.Fatalf("the interrupted clone left no journal: %v\n%s", err, interrupt.log.String())
	}
	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if rep.Resumed < 2 || rep.Added == 0 || !strings.Contains(log.String(), "resuming: the journal "+journal+" holds") {
		t.Fatalf("the resumed clone: %+v\n%s", rep, log.String())
	}
	if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a complete clone keeps its journal: %v", err)
	}
	var diffOut bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &diffOut); err != nil || code != app.ExitSame {
		t.Fatalf("diff after the resumed clone: %d %v\n%s", code, err, diffOut.String())
	}
}

// stopAfterUsers cancels the run once the log has said left times that it added an entry whose line starts so.
type stopAfterUsers struct {
	left   int
	prefix string
	stop   context.CancelFunc
	log    bytes.Buffer
}

func (w *stopAfterUsers) Write(p []byte) (int, error) {
	w.log.Write(p)
	if w.left > 0 && bytes.Contains(p, []byte(w.prefix)) {
		if w.left--; w.left == 0 {
			w.stop()
		}
	}
	return len(p), nil
}

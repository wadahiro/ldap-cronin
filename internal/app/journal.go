package app

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// journalFingerprint identifies the dump and the config a journal is valid for: what an earlier run finished is
// done only for the same entries written the same way. A server may change between runs, so it has none
// (ok=false). The fixed password is left out, the config being hashed as a whole, and so is [run]: the workers and
// where the journal is kept do not change what is written, and a run after one stopped by a busy server may well
// take fewer workers.
func (s *Session) journalFingerprint() (string, bool) {
	m, ok := s.dumpMeta()
	if !ok {
		return "", false
	}
	cfg := *s.Cfg
	cfg.Accounts.FixedPassword = ""
	cfg.Run = config.Run{}
	b, err := json.Marshal(cfg)
	if err != nil {
		return "", false
	}
	h := sha256.New()
	h.Write(b)
	size := int64(-1)
	if st, err := os.Stat(s.Cfg.Source.LDIF); err == nil {
		size = st.Size()
	}
	fmt.Fprintf(h, "\n%s\n%s\n%d\n%d", m.Server, m.DumpedAt, m.Entries, size)
	return hex.EncodeToString(h.Sum(nil)), true
}

// journalPath is where a clone over LDAP keeps its journal: [run] journal, else beside the config file, so two
// configs in one directory keep two journals. "" when neither is known (a session not opened from a file).
func (s *Session) journalPath() string {
	if s.Cfg.Run.Journal != "" {
		return s.Cfg.Run.Journal
	}
	if s.ConfigPath == "" {
		return ""
	}
	return s.ConfigPath + ".journal"
}

// journalHeader starts a journal file; another version's is taken for a journal of something else, and dropped.
const journalHeader = "# ldap-cronin journal v1"

// fileJournal is the journal of a clone over LDAP from a dump, in a local file: the keys clone marks (quoted, one
// per line), and after each batch of them the target's generation (profile.GenerationReader) read just then.
// Unlike a native import's, it is not inside the target, so a target made anew or restored to an earlier point
// would keep a journal of objects it lacks: it is dropped when the target's identifier differs from the one it
// was kept for, or the target's number of writes is below the last one recorded.
type fileJournal struct {
	path        string
	fingerprint string
	id          string // the target's
	gen         profile.GenerationReader
	dst         directory.Directory
	root        string
	// done is what the file held when read; never changed after, so Has, called by every worker, takes no lock.
	done map[string]bool
	// Stale says the file held a journal of another dump, config or target, or of this target before it was
	// restored to an earlier point; start drops it.
	Stale bool

	mu      sync.Mutex
	f       *os.File
	w       *bufio.Writer
	pending []string
}

// loadJournal reads the journal at path for fingerprint and the target dst, whose generation is id and usn now,
// without writing anything: the file is written from start on, after the run was confirmed.
func loadJournal(path, fingerprint, id string, usn int64, gen profile.GenerationReader, dst directory.Directory, root string) (*fileJournal, error) {
	j := &fileJournal{path: path, fingerprint: fingerprint, id: id, gen: gen, dst: dst, root: root, done: map[string]bool{}}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	if !sc.Scan() || sc.Text() != j.header() {
		j.Stale = true
		return j, nil
	}
	last := int64(-1)
	for sc.Scan() {
		line := sc.Text()
		if n, ok := strings.CutPrefix(line, "usn "); ok {
			if last, err = strconv.ParseInt(n, 10, 64); err != nil {
				j.Stale = true
				return j, nil
			}
			continue
		}
		key, err := strconv.Unquote(line)
		if err != nil {
			// A line cut off by a run that ended mid-write: the keys before it hold.
			break
		}
		j.done[key] = true
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if usn < last {
		j.Stale = true
	}
	if j.Stale {
		j.done = map[string]bool{}
	}
	return j, nil
}

func (j *fileJournal) header() string {
	return fmt.Sprintf("%s fingerprint=%s target=%s", journalHeader, j.fingerprint, j.id)
}

// Len is how many keys the file held when it was read.
func (j *fileJournal) Len() int { return len(j.done) }

// start opens the file for the keys of this run: appended to the ones read, or, for a new or stale journal, after
// a new header.
func (j *fileJournal) start() error {
	var err error
	if len(j.done) > 0 {
		j.f, err = os.OpenFile(j.path, os.O_WRONLY|os.O_APPEND, 0o600)
		if err == nil {
			j.w = bufio.NewWriter(j.f)
			// A line cut off by a run that ended mid-write is ended, so the next key is a line of its own.
			_, err = j.w.WriteString("\n")
		}
	} else {
		j.f, err = os.OpenFile(j.path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err == nil {
			j.w = bufio.NewWriter(j.f)
			_, err = j.w.WriteString(j.header() + "\n")
		}
	}
	if err != nil {
		return fmt.Errorf("journal %s: %w", j.path, err)
	}
	return j.w.Flush()
}

func (j *fileJournal) Has(key string) bool { return j.done[key] }

func (j *fileJournal) Mark(ctx context.Context, key string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.pending = append(j.pending, key)
	if len(j.pending) < journalBatch {
		return nil
	}
	return j.flush(ctx)
}

// journalBatch is how many keys are written at once, each batch followed by the target's number of writes, read
// once per batch; a key not yet written is only compared again by the next run.
const journalBatch = 500

// Flush writes the keys not yet written.
func (j *fileJournal) Flush(ctx context.Context) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.flush(ctx)
}

func (j *fileJournal) flush(ctx context.Context) error {
	if len(j.pending) == 0 || j.w == nil {
		return nil
	}
	if err := j.write(ctx); err != nil {
		return fmt.Errorf("journal %s: %w", j.path, err)
	}
	j.pending = j.pending[:0]
	return nil
}

func (j *fileJournal) write(ctx context.Context) error {
	for _, k := range j.pending {
		if _, err := j.w.WriteString(strconv.Quote(k) + "\n"); err != nil {
			return err
		}
	}
	// Read after the writes the keys stand for: a target restored to before them has fewer. Unread (the target
	// gone), the keys are kept all the same, the number recorded before them still guarding them.
	_, usn, err := j.gen.Generation(ctx, j.dst, j.root)
	if err != nil {
		return errors.Join(err, j.w.Flush())
	}
	if _, err := fmt.Fprintf(j.w, "usn %d\n", usn); err != nil {
		return err
	}
	if err := j.w.Flush(); err != nil {
		return err
	}
	return j.f.Sync()
}

// Close closes the file, keeping it.
func (j *fileJournal) Close() error {
	if j.f == nil {
		return nil
	}
	err := j.f.Close()
	j.f, j.w = nil, nil
	return err
}

// Remove removes the file: the clone is complete, and the next one compares everything again.
func (j *fileJournal) Remove() error {
	if err := j.Close(); err != nil {
		return err
	}
	if err := os.Remove(j.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// openJournal reads the journal of a clone over LDAP into dst, saying on log whether it resumes or why there is
// none; nil when the run keeps none.
func (s *Session) openJournal(ctx context.Context, dst directory.Directory, job plan.Job, log io.Writer) (*fileJournal, error) {
	fp, ok := s.journalFingerprint()
	if !ok {
		if s.TimeLimit > 0 {
			fmt.Fprintln(s.Warn, "note: the source is a server, which may change between runs, so a run after -time-limit compares every object again (from a dump it goes on where it stopped)")
		}
		return nil, nil
	}
	path, gen := s.journalPath(), job.Profile.Generation
	if path == "" || gen == nil {
		return nil, nil
	}
	root, err := plan.Root(ctx, dst, job)
	if err != nil {
		return nil, err
	}
	id, usn, err := gen.Generation(ctx, dst, root)
	if err != nil {
		fmt.Fprintf(s.Warn, "note: no journal is kept, as the target does not say which it is (%v): a run after an interrupted one compares every object again\n", err)
		return nil, nil
	}
	j, err := loadJournal(path, fp, id, usn, gen, dst, root)
	if err != nil {
		return nil, fmt.Errorf("journal %s: %w", path, err)
	}
	if j.Stale {
		fmt.Fprintf(log, "note: the journal %s was of another dump, config or target, or the target was restored to an earlier point: it is dropped, and every object is compared\n", path)
	}
	if j.Len() > 0 {
		fmt.Fprintf(log, "resuming: the journal %s holds %d objects and reference passes an earlier run finished; they are skipped\n", path, j.Len())
	}
	return j, nil
}

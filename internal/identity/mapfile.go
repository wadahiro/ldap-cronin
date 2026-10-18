// The mapping file keeps the source and target identifiers of each cloned object in a local file
// ([mapping] mode = "file", for servers on which clone can neither keep the identifier nor write a marker).
//
// A DN change on the target does not change the identifier, so with the mapping diff can detect that
// "the object at this DN on the source lives at a different DN on the target".
//
// The file is a ledger, not a state: it holds every (source key, target key) pair clone ever recorded, and a source
// key may have several target keys. A target can be rewound (a lab restore, or another instance restored from the
// same snapshot) to the keys of an earlier clone; servers never reuse an identifier, so a key once recorded for a
// source object can only reappear as that object. Restores, sibling instances and recreated targets therefore need
// nothing, and one file serves every target cloned from one source.
//
// The table is a file of fixed-length records, one pair each, sorted by (source, target). Reading does a binary
// search on the file instead of loading everything, so memory stays constant regardless of the entry count. clone
// appends new pairs to a separate file and, on exit, merges them with the existing table via an external sort (sort
// per chunk, then merge) and rewrites it. A lock file keeps two clones from rewriting the table at once.
package identity

import (
	"bufio"
	"container/heap"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	guidHexLen = 32               // hex notation of a 16-byte key
	recordLen  = guidHexLen*2 + 2 // "source\ttarget\n"; fixed length lets us compute a record position
	deltaSufix = ".delta"
	lockSuffix = ".lock"
)

// chunkRecords is the number of records held in memory at once by the external sort. Tests make it small.
var chunkRecords = 200_000

// formatVersion is written into every header. A file of another version is refused rather than misread.
const formatVersion = 5

// headerPrefix starts every header line, of this version and of older ones, so an old file is recognized as such.
const headerPrefix = "# ldap-cronin "

// Header says which source the table belongs to. It is checked so a table of another source is never read.
//
// The source is identified by the key of its naming-context root (RootKey), not by its URL. The target is not
// recorded: keys are globally unique, so pairs of another target (or base_dn) simply never match, and one file
// serves every target cloned from the source. The scheme is recorded too, so keys recorded as objectGUID are never
// looked up as entryUUID.
type Header struct {
	Scheme     string // Scheme.Attr()
	SourceRoot Key
}

func (h Header) line() string {
	return fmt.Sprintf("%smapping v%d scheme=%s source-root=%s", headerPrefix, formatVersion, h.Scheme, h.SourceRoot)
}

// ErrHeaderMismatch means the table belongs to another source (or scheme).
var ErrHeaderMismatch = errors.New("mapping file belongs to another source")

// ErrInUse means another clone holds the file's lock.
var ErrInUse = errors.New("mapping file is in use by another clone")

// ErrOldFormat means the file was written by another version of the tool. There is no converter: clone again.
var ErrOldFormat = errors.New("mapping file was written in another format; run clone again to record a new one")

type record struct{ key, val string }

func (r record) less(o record) bool { return r.key < o.key || r.key == o.key && r.val < o.val }

type Map struct {
	path   string
	hdr    Header
	locked bool // Open took the lock file; Close removes it

	main    *os.File // sorted table; nil if it does not exist yet
	dataOff int64
	count   int64

	mu       sync.Mutex // guards appends
	delta    *os.File
	deltaOut *bufio.Writer
}

// Load opens the table read-only. It returns os.ErrNotExist if the file does not exist.
func Load(path string, h Header) (*Map, error) {
	m := &Map{path: path, hdr: h}
	if err := m.openMain(); err != nil {
		return nil, err
	}
	if m.main == nil {
		return nil, os.ErrNotExist
	}
	return m, nil
}

// Open is for clone. It takes the lock file and opens the existing table so new pairs can be appended.
// If a table of another source exists, it returns ErrHeaderMismatch rather than overwrite it; if another clone holds
// the lock, ErrInUse. If a previous clone ended midway and left an append file, that is merged into the table first.
func Open(path string, h Header) (*Map, error) {
	m := &Map{path: path, hdr: h}
	if err := m.lock(); err != nil {
		return nil, err
	}
	m.locked = true
	if err := m.open(); err != nil {
		if m.main != nil {
			m.main.Close()
		}
		m.unlock()
		return nil, err
	}
	return m, nil
}

func (m *Map) open() error {
	if err := m.openMain(); err != nil {
		return err
	}
	if st, err := os.Stat(m.path + deltaSufix); err == nil && st.Size() > 0 {
		if err := m.compact(); err != nil {
			return fmt.Errorf("merge leftover %s: %w", m.path+deltaSufix, err)
		}
	}
	f, err := os.OpenFile(m.path+deltaSufix, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	m.delta, m.deltaOut = f, bufio.NewWriter(f)
	return nil
}

// lock creates the lock file exclusively (O_EXCL works on every platform). It records who holds it, so a lock left
// by a killed clone can be told from a running one.
func (m *Map) lock() error {
	f, err := os.OpenFile(m.path+lockSuffix, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		held, _ := os.ReadFile(m.path + lockSuffix)
		return fmt.Errorf("%w (%s: %s); if no clone is running, delete it", ErrInUse, m.path+lockSuffix, strings.TrimSpace(string(held)))
	}
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	_, err = fmt.Fprintf(f, "pid %d on %s since %s\n", os.Getpid(), host, time.Now().Format(time.RFC3339))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(m.path + lockSuffix)
	}
	return err
}

func (m *Map) unlock() {
	if m.locked {
		os.Remove(m.path + lockSuffix)
		m.locked = false
	}
}

// openMain opens the sorted table and checks its header and size. If it does not exist, main stays nil.
func (m *Map) openMain() error {
	if m.main != nil {
		m.main.Close()
		m.main = nil
	}
	f, err := os.Open(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	br := bufio.NewReader(f)
	line, err := br.ReadString('\n')
	if err != nil {
		f.Close()
		return fmt.Errorf("read header of %s: %w", m.path, err)
	}
	got := strings.TrimRight(line, "\n")
	if !strings.HasPrefix(got, fmt.Sprintf("%smapping v%d ", headerPrefix, formatVersion)) {
		f.Close()
		return fmt.Errorf("%s: %w (header: %q)", m.path, ErrOldFormat, got)
	}
	if got != m.hdr.line() {
		f.Close()
		return fmt.Errorf("%w (file: %q)", ErrHeaderMismatch, got)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	off := int64(len(line))
	if (st.Size()-off)%recordLen != 0 {
		f.Close()
		return fmt.Errorf("%s is corrupt: size does not match the fixed record length", m.path)
	}
	m.main, m.dataOff, m.count = f, off, (st.Size()-off)/recordLen
	return nil
}

// Targets returns every target key recorded for a source key, by binary search on the file. It is safe to call from
// multiple goroutines.
func (m *Map) Targets(source Key) []Key {
	var keys []Key
	for _, t := range m.targets(source.String()) {
		if k, err := ParseHex(t); err == nil {
			keys = append(keys, k)
		}
	}
	return keys
}

// scanRecords is how many records are read at once after the binary search: a source with one target key (nearly
// every one) is answered by one read that also shows the next record is another source's.
const scanRecords = 2

func (m *Map) targets(source string) []string {
	if m.main == nil || len(source) != guidHexLen {
		return nil
	}
	buf := make([]byte, recordLen)
	i := sort.Search(int(m.count), func(i int) bool {
		if _, err := m.main.ReadAt(buf, m.dataOff+int64(i)*recordLen); err != nil {
			return true
		}
		return string(buf[:guidHexLen]) >= source
	})
	var found []string
	buf = make([]byte, recordLen*scanRecords)
	for ; i < int(m.count); i += scanRecords {
		n := min(scanRecords, int(m.count)-i)
		if _, err := m.main.ReadAt(buf[:n*recordLen], m.dataOff+int64(i)*recordLen); err != nil {
			return found
		}
		for r := 0; r < n; r++ {
			rec := buf[r*recordLen : (r+1)*recordLen]
			if string(rec[:guidHexLen]) != source {
				return found
			}
			found = append(found, string(rec[guidHexLen+1:guidHexLen*2+1]))
		}
	}
	return found
}

// Len is the number of pairs in the sorted table (pairs appended during clone are not counted until it finishes).
func (m *Map) Len() int { return int(m.count) }

// Record appends only a new pair, so re-runs do not make the table grow; a pair is never replaced. A zero key on
// either side (an object without an identifier) is not recorded.
func (m *Map) Record(source, target Key) error {
	if source.IsZero() || target.IsZero() {
		return nil
	}
	if slices.Contains(m.Targets(source), target) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := fmt.Fprintf(m.deltaOut, "%s\t%s\n", source, target)
	return err
}

// Close sorts the appended pairs, merges them into the table, rewrites it and releases the lock. For a table opened
// read-only it only closes.
func (m *Map) Close() error {
	if m.delta == nil {
		if m.main != nil {
			return m.main.Close()
		}
		return nil
	}
	defer m.unlock()
	err := m.deltaOut.Flush()
	if cerr := m.delta.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		// On failure (on Windows the rename fails while a diff holds the table open) the pairs stay in the append
		// file, and the next Open merges them.
		err = m.compact()
	}
	if m.main != nil {
		if cerr := m.main.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// compact externally sorts the append file, merges it with the existing table and rewrites it (identical pairs once).
func (m *Map) compact() error {
	runs, err := m.sortDeltaIntoRuns()
	if err != nil {
		return err
	}
	defer func() {
		for _, r := range runs {
			os.Remove(r)
		}
	}()

	var sources []*recordReader
	defer func() {
		for _, s := range sources {
			s.close()
		}
	}()
	if m.main != nil {
		f, err := os.Open(m.path)
		if err != nil {
			return err
		}
		if _, err := f.Seek(m.dataOff, io.SeekStart); err != nil {
			f.Close()
			return err
		}
		sources = append(sources, newRecordReader(f))
	}
	for _, r := range runs {
		f, err := os.Open(r)
		if err != nil {
			return err
		}
		sources = append(sources, newRecordReader(f))
	}

	tmp := m.path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(out)
	fmt.Fprintln(w, m.hdr.line())
	if err := merge(sources, w); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := w.Flush(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if m.main != nil {
		m.main.Close()
		m.main = nil
	}
	if err := os.Rename(tmp, m.path); err != nil {
		os.Remove(tmp)
		return err
	}
	os.Remove(m.path + deltaSufix)
	return m.openMain()
}

// sortDeltaIntoRuns sorts the append file chunkRecords records at a time and writes each chunk to a sorted temporary file.
// Within a chunk identical pairs are written once.
func (m *Map) sortDeltaIntoRuns() ([]string, error) {
	f, err := os.Open(m.path + deltaSufix)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rr := newRecordReader(f)

	var runs []string
	fail := func(err error) ([]string, error) {
		for _, r := range runs {
			os.Remove(r)
		}
		return nil, err
	}
	for {
		chunk := make([]record, 0, min(chunkRecords, 4096))
		for len(chunk) < chunkRecords {
			rec, ok, err := rr.next()
			if err != nil {
				return fail(err)
			}
			if !ok {
				break
			}
			chunk = append(chunk, rec)
		}
		if len(chunk) == 0 {
			return runs, nil
		}
		sort.Slice(chunk, func(i, j int) bool { return chunk[i].less(chunk[j]) })
		run, err := os.CreateTemp(filepath.Dir(m.path), filepath.Base(m.path)+".run*")
		if err != nil {
			return fail(err)
		}
		runs = append(runs, run.Name())
		w := bufio.NewWriter(run)
		for i, rec := range chunk {
			if i > 0 && chunk[i-1] == rec {
				continue
			}
			fmt.Fprintf(w, "%s\t%s\n", rec.key, rec.val)
		}
		if err := w.Flush(); err != nil {
			run.Close()
			return fail(err)
		}
		if err := run.Close(); err != nil {
			return fail(err)
		}
	}
}

type recordReader struct {
	f *os.File
	r *bufio.Reader
}

func newRecordReader(f *os.File) *recordReader {
	return &recordReader{f: f, r: bufio.NewReaderSize(f, 1<<16)}
}
func (r *recordReader) close() { r.f.Close() }

func (r *recordReader) next() (record, bool, error) {
	buf := make([]byte, recordLen)
	if _, err := io.ReadFull(r.r, buf); err != nil {
		if errors.Is(err, io.EOF) {
			return record{}, false, nil
		}
		return record{}, false, fmt.Errorf("truncated record: %w", err)
	}
	if buf[guidHexLen] != '\t' || buf[recordLen-1] != '\n' {
		return record{}, false, fmt.Errorf("malformed record %q", buf)
	}
	return record{key: string(buf[:guidHexLen]), val: string(buf[guidHexLen+1 : guidHexLen*2+1])}, true, nil
}

type item struct {
	rec record
	src int
}

type mergeHeap []item

func (h mergeHeap) Len() int           { return len(h) }
func (h mergeHeap) Less(i, j int) bool { return h[i].rec.less(h[j].rec) }
func (h mergeHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *mergeHeap) Push(x any)        { *h = append(*h, x.(item)) }
func (h *mergeHeap) Pop() any {
	old := *h
	it := old[len(old)-1]
	*h = old[:len(old)-1]
	return it
}

// merge merges several sorted inputs into one in (source, target) order, writing identical pairs once.
func merge(sources []*recordReader, w io.Writer) error {
	h := &mergeHeap{}
	push := func(i int) error {
		rec, ok, err := sources[i].next()
		if err != nil {
			return err
		}
		if ok {
			heap.Push(h, item{rec: rec, src: i})
		}
		return nil
	}
	for i := range sources {
		if err := push(i); err != nil {
			return err
		}
	}
	var last record
	wrote := false
	for h.Len() > 0 {
		it := heap.Pop(h).(item)
		if err := push(it.src); err != nil {
			return err
		}
		if wrote && it.rec == last {
			continue
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\n", it.rec.key, it.rec.val); err != nil {
			return err
		}
		last, wrote = it.rec, true
	}
	return nil
}

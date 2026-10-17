// The mapping file keeps the source and target identifiers of each cloned object in a local file.
//
// Nothing is written to the target objects (borrowing an attribute would collide with how the target uses its attributes).
// A DN change on the target does not change the identifier, so with the mapping diff can detect that
// "the object at this DN on the source lives at a different DN on the target".
//
// The table is a file of fixed-length records sorted by source key. Reading does a binary search
// on the file instead of loading everything, so memory stays constant regardless of the entry count. clone appends new mappings to a separate file and,
// on exit, merges them with the existing table via an external sort (sort per chunk, then merge) and rewrites it.
//
// A stale mapping (e.g. the target was rebuilt) only means lookups miss; it never causes a false detection.
package identity

import (
	"bufio"
	"container/heap"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	guidHexLen = 32               // hex notation of a 16-byte key
	recordLen  = guidHexLen*2 + 2 // "source\ttarget\n"; fixed length lets us compute a record position
	deltaSufix = ".delta"
)

// chunkRecords is the number of records held in memory at once by the external sort. Tests make it small.
var chunkRecords = 200_000

// formatVersion is written into every header. A file of another version is refused rather than misread.
const formatVersion = 4

// headerPrefix starts every header line, of this version and of older ones, so an old file is recognized as such.
const headerPrefix = "# ldap-cronin "

// Header says which source/target pair the table belongs to. It is checked so a table for another pair is never read.
//
// The pair is identified by the keys of the naming-context roots (RootKey), not by connection URLs: the URL changes
// when the lab is rebuilt or started from a snapshot on another port, while the data, and the mapping, stay valid.
// The scheme is recorded too, so keys recorded as objectGUID are never looked up as entryUUID.
type Header struct {
	Scheme     string // Scheme.Attr()
	SourceRoot Key
	TargetRoot Key
	BaseDN     string
}

func (h Header) line() string {
	return fmt.Sprintf("%smapping v%d scheme=%s source-root=%s target-root=%s base_dn=%s",
		headerPrefix, formatVersion, h.Scheme, h.SourceRoot, h.TargetRoot, h.BaseDN)
}

// ErrHeaderMismatch means the table belongs to a different source/target pair.
var ErrHeaderMismatch = errors.New("mapping file belongs to a different source/target/base_dn")

// ErrOldFormat means the file was written by another version of the tool. There is no converter: clone again.
var ErrOldFormat = errors.New("mapping file was written in another format; run clone again to record a new one")

type record struct{ key, val string }

type Map struct {
	path string
	hdr  Header

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

// Open is for clone. It opens the existing table so new mappings can be appended.
// If a table for a different source/target pair exists, it returns ErrHeaderMismatch rather than overwrite it.
// If a previous clone ended midway and left an append file, that is merged into the table first.
func Open(path string, h Header) (*Map, error) {
	m := &Map{path: path, hdr: h}
	if err := m.openMain(); err != nil {
		return nil, err
	}
	if st, err := os.Stat(path + deltaSufix); err == nil && st.Size() > 0 {
		if err := m.compact(); err != nil {
			return nil, fmt.Errorf("merge leftover %s: %w", path+deltaSufix, err)
		}
	}
	f, err := os.OpenFile(path+deltaSufix, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	m.delta, m.deltaOut = f, bufio.NewWriter(f)
	return m, nil
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

// Target returns the target key for a source key by binary search on the file. It is safe to call from multiple goroutines.
func (m *Map) Target(source Key) (Key, bool) {
	t, ok := m.target(source.String())
	if !ok {
		return Key{}, false
	}
	k, err := ParseHex(t)
	return k, err == nil
}

func (m *Map) target(source string) (string, bool) {
	if m.main == nil || len(source) != guidHexLen {
		return "", false
	}
	buf := make([]byte, recordLen)
	i := sort.Search(int(m.count), func(i int) bool {
		if _, err := m.main.ReadAt(buf, m.dataOff+int64(i)*recordLen); err != nil {
			return true
		}
		return string(buf[:guidHexLen]) >= source
	})
	if i >= int(m.count) {
		return "", false
	}
	if _, err := m.main.ReadAt(buf, m.dataOff+int64(i)*recordLen); err != nil {
		return "", false
	}
	if string(buf[:guidHexLen]) != source {
		return "", false
	}
	return string(buf[guidHexLen+1 : guidHexLen*2+1]), true
}

// Len is the number of records in the sorted table (entries appended during clone are not counted until it finishes).
func (m *Map) Len() int { return int(m.count) }

// Record appends only a new or changed mapping, so re-runs do not make the table grow. A zero key on either side
// (an object without an identifier) is not recorded.
func (m *Map) Record(source, target Key) error {
	if source.IsZero() || target.IsZero() {
		return nil
	}
	if cur, ok := m.Target(source); ok && cur == target {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := fmt.Fprintf(m.deltaOut, "%s\t%s\n", source, target)
	return err
}

// Close sorts the appended entries, merges them into the table and rewrites it. For a table opened read-only it only closes.
func (m *Map) Close() error {
	if m.delta == nil {
		if m.main != nil {
			return m.main.Close()
		}
		return nil
	}
	if err := m.deltaOut.Flush(); err != nil {
		return err
	}
	if err := m.delta.Close(); err != nil {
		return err
	}
	if err := m.compact(); err != nil {
		return err
	}
	if m.main != nil {
		return m.main.Close()
	}
	return nil
}

// compact externally sorts the append file, merges it with the existing table and rewrites it (for the same key the newer one wins).
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
		return err
	}
	os.Remove(m.path + deltaSufix)
	return m.openMain()
}

// sortDeltaIntoRuns sorts the append file chunkRecords records at a time and writes each chunk to a sorted temporary file.
// The returned order is creation order; later runs are newer.
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
		sort.SliceStable(chunk, func(i, j int) bool { return chunk[i].key < chunk[j].key })
		run, err := os.CreateTemp(filepath.Dir(m.path), filepath.Base(m.path)+".run*")
		if err != nil {
			return fail(err)
		}
		runs = append(runs, run.Name())
		w := bufio.NewWriter(run)
		for i, rec := range chunk {
			if i+1 < len(chunk) && chunk[i+1].key == rec.key {
				continue // for the same key keep only the later (newer) append
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
	src int // larger means newer
}

type mergeHeap []item

func (h mergeHeap) Len() int { return len(h) }
func (h mergeHeap) Less(i, j int) bool {
	if h[i].rec.key != h[j].rec.key {
		return h[i].rec.key < h[j].rec.key
	}
	return h[i].src > h[j].src
}
func (h mergeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *mergeHeap) Push(x any)   { *h = append(*h, x.(item)) }
func (h *mergeHeap) Pop() any {
	old := *h
	it := old[len(old)-1]
	*h = old[:len(old)-1]
	return it
}

// merge merges several sorted inputs into one in key order. For the same key, the one with the larger src (newer) is kept.
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
	last := ""
	wrote := false
	for h.Len() > 0 {
		it := heap.Pop(h).(item)
		if err := push(it.src); err != nil {
			return err
		}
		if wrote && it.rec.key == last {
			continue // the newer one was written first, so drop the older entry with the same key
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\n", it.rec.key, it.rec.val); err != nil {
			return err
		}
		last, wrote = it.rec.key, true
	}
	return nil
}

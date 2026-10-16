// Package guidmap keeps a mapping between the object GUIDs of the clone source and the target in a local file.
//
// Nothing is written to the target objects (borrowing an attribute would collide with how the target uses its attributes).
// A DN change on the target does not change objectGUID, so with the mapping diff can detect that
// "the object at this DN on the source lives at a different DN on the target".
//
// The table is a file of fixed-length records sorted by source GUID. Reading does a binary search
// on the file instead of loading everything, so memory stays constant regardless of the entry count. clone appends new mappings to a separate file and,
// on exit, merges them with the existing table via an external sort (sort per chunk, then merge) and rewrites it.
//
// A stale mapping (e.g. the target was rebuilt) only means GUID lookups miss; it never causes a false detection.
package guidmap

import (
	"bufio"
	"container/heap"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
)

const (
	guidHexLen = 32               // hex notation of a 16-byte GUID
	recordLen  = guidHexLen*2 + 2 // "source\ttarget\n"; fixed length lets us compute a record position
	deltaSufix = ".delta"
)

// chunkRecords is the number of records held in memory at once by the external sort. Tests make it small.
var chunkRecords = 200_000

// Header says which source/target pair the table belongs to. It is checked so a table for another pair is never read.
//
// The identifier is the domain itself (the objectGUID of the domain root; DomainID), not the connection URL.
// The URL (host name, port) changes when the lab is rebuilt or started from a snapshot on another port,
// while the domain data stays the same and the mapping remains valid. A different domain has a different identifier and is rejected.
type Header struct {
	SourceDomain string
	TargetDomain string
	BaseDN       string
}

func (h Header) line() string {
	return fmt.Sprintf("# ldap-cronin guid-map v3 source-domain=%s target-domain=%s base_dn=%s", h.SourceDomain, h.TargetDomain, h.BaseDN)
}

// DomainID returns a string identifying the AD domain of baseDN (the objectGUID of the domain root).
func DomainID(d directory.Directory, baseDN string) (string, error) {
	return RootID(d, dn.DomainRoot(baseDN), "objectGUID")
}

// RootID returns a string identifying the naming context rooted at root: the value of its identifier attribute
// (objectGUID, entryUUID). Two servers are the same directory exactly when this matches.
func RootID(d directory.Directory, root, idAttr string) (string, error) {
	e, err := d.Get(root, []string{idAttr})
	if err != nil {
		return "", fmt.Errorf("cannot read root %s: %w", root, err)
	}
	if e == nil {
		return "", fmt.Errorf("root %s not found", root)
	}
	vals := e.Values(idAttr)
	if len(vals) == 0 || vals[0] == "" {
		return "", fmt.Errorf("root %s has no %s", root, idAttr)
	}
	return Hex(vals[0]), nil
}

// ErrHeaderMismatch means the table belongs to a different source/target pair.
var ErrHeaderMismatch = errors.New("mapping file belongs to a different source/target/base_dn")

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

// Hex converts an object identifier into a hex string (32 characters). Empty input yields an empty string.
// AD returns objectGUID as 16 raw bytes; other servers return entryUUID as text ("8-4-4-4-12"), which is
// converted to the same 16 bytes first so that both fit the fixed-size table.
func Hex(raw string) string {
	if raw == "" {
		return ""
	}
	if h, ok := uuidHex(raw); ok {
		return h
	}
	return hex.EncodeToString([]byte(raw))
}

// uuidHex returns the 32 hex digits of a UUID in text notation.
func uuidHex(s string) (string, bool) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return "", false
	}
	h := strings.ReplaceAll(s, "-", "")
	if _, err := hex.DecodeString(h); err != nil {
		return "", false
	}
	return strings.ToLower(h), true
}

// UUIDText is the inverse of Hex for text identifiers: 32 hex digits to "8-4-4-4-12". Used in search filters for entryUUID.
func UUIDText(h string) string {
	if len(h) != 32 {
		return h
	}
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// FilterValue converts a hex string into the LDAP filter notation for a binary value (\ab\cd...).
func FilterValue(h string) string {
	var b strings.Builder
	for i := 0; i+1 < len(h); i += 2 {
		b.WriteString(`\` + h[i:i+2])
	}
	return b.String()
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
	if strings.TrimRight(line, "\n") != m.hdr.line() {
		f.Close()
		return fmt.Errorf("%w (file: %q)", ErrHeaderMismatch, strings.TrimRight(line, "\n"))
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

// Target returns the target GUID for a source GUID by binary search on the file. It is safe to call from multiple goroutines.
func (m *Map) Target(source string) (string, bool) {
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

// Record appends only a new or changed mapping, so re-runs do not make the table grow.
func (m *Map) Record(source, target string) error {
	if source == "" || target == "" {
		return nil
	}
	if len(source) != guidHexLen || len(target) != guidHexLen {
		return fmt.Errorf("invalid GUID length: %q -> %q", source, target)
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

// Lookup maps a source GUID (Hex) to a target GUID.
type Lookup interface {
	Target(source string) (string, bool)
	Len() int
}

// Identity is the mapping "the target GUID equals the source GUID". It is used when a native import preserved objectGUID.
// No mapping file is needed.
type Identity struct{}

func (Identity) Target(source string) (string, bool) { return source, source != "" }
func (Identity) Len() int                            { return 0 }

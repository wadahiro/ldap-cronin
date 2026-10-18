package identity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/fakedir"
)

var hdr = Header{Scheme: "objectGUID", SourceRoot: g(0xaa)}

func g(n int) Key {
	k, err := ParseHex(fmt.Sprintf("%032x", n))
	if err != nil {
		panic(err)
	}
	return k
}

func TestRecordPersistsAcrossRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.tsv")
	m, err := Open(path, hdr)
	if err != nil {
		t.Fatal(err)
	}
	m.Record(g(1), g(101))
	m.Record(g(2), g(102))
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path, hdr)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if got := loaded.Targets(g(1)); !slices.Equal(got, []Key{g(101)}) || loaded.Len() != 2 {
		t.Fatalf("got %s len=%d", got, loaded.Len())
	}
	if got := loaded.Targets(g(3)); got != nil {
		t.Fatal("unknown GUID must not be found")
	}
}

func TestFileIsSortedBySourceGUIDWithFixedLengthRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.tsv")
	m, _ := Open(path, hdr)
	for _, n := range []int{5, 1, 9, 3, 7} { // record deliberately out of order
		m.Record(g(n), g(n+1000))
	}
	m.Close()
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")[1:]
	if !sort.StringsAreSorted(lines) {
		t.Fatalf("not sorted: %v", lines)
	}
	for _, l := range lines {
		if len(l)+1 != recordLen {
			t.Fatalf("record %q is not fixed length", l)
		}
	}
}

func TestRerunDoesNotGrowTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.tsv")
	var sizes []int64
	for i := 0; i < 3; i++ {
		m, err := Open(path, hdr)
		if err != nil {
			t.Fatal(err)
		}
		m.Record(g(1), g(101))
		m.Close()
		st, _ := os.Stat(path)
		sizes = append(sizes, st.Size())
	}
	if sizes[0] != sizes[1] || sizes[1] != sizes[2] {
		t.Fatalf("file grew on re-run: %v", sizes)
	}
}

// The file is a ledger: a source cloned again (the program recreated it, or another target) keeps every target key,
// since a restore can bring an earlier one back.
func TestRecloneKeepsEveryPair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.tsv")
	m, _ := Open(path, hdr)
	m.Record(g(1), g(101))
	m.Record(g(2), g(102))
	m.Close()
	m, _ = Open(path, hdr)
	m.Record(g(1), g(999))
	m.Record(g(1), g(101)) // already recorded
	m.Close()
	loaded, _ := Load(path, hdr)
	defer loaded.Close()
	if got := loaded.Targets(g(1)); !slices.Equal(got, []Key{g(101), g(999)}) || loaded.Len() != 3 {
		t.Fatalf("got %s len=%d", got, loaded.Len())
	}
	if got := loaded.Targets(g(2)); !slices.Equal(got, []Key{g(102)}) {
		t.Fatalf("a neighbour's pairs must not leak: %s", got)
	}
}

// Lookups end exactly at a source's last pair, at the first and last record and across the two-record reads.
func TestTargetsFindEveryPairOfASourceAndNoneOfItsNeighbours(t *testing.T) {
	old := chunkRecords
	chunkRecords = 3
	defer func() { chunkRecords = old }()
	path := filepath.Join(t.TempDir(), "map.tsv")
	want := map[int][]Key{1: {g(11)}, 2: {g(21), g(22), g(23)}, 3: {g(31), g(32)}, 4: {g(41)}}
	m, _ := Open(path, hdr)
	for _, n := range []int{4, 2, 3, 1} {
		for i := len(want[n]) - 1; i >= 0; i-- { // reverse, across chunks: the merge must still sort
			m.Record(g(n), want[n][i])
		}
	}
	m.Close()
	loaded, _ := Load(path, hdr)
	defer loaded.Close()
	for n, keys := range want {
		if got := loaded.Targets(g(n)); !slices.Equal(got, keys) {
			t.Errorf("source %d: got %s, want %s", n, got, keys)
		}
	}
	for _, n := range []int{0x10, 5} {
		if got := loaded.Targets(g(n)); got != nil {
			t.Errorf("source %d is not recorded: %s", n, got)
		}
	}
}

// Use small chunks to exercise merging of multiple sorted files and merging with the existing table.
func TestExternalSortMergesManyRunsAndExistingTable(t *testing.T) {
	old := chunkRecords
	chunkRecords = 50
	defer func() { chunkRecords = old }()

	path := filepath.Join(t.TempDir(), "map.tsv")
	const n = 2000
	rng := rand.New(rand.NewSource(1))
	order := rng.Perm(n)

	m, _ := Open(path, hdr)
	for _, i := range order[:n/2] { // first run: half (keys start at 1: the zero key means "none")
		m.Record(g(i+1), g(i+100000))
	}
	m.Close()
	m, _ = Open(path, hdr)
	for _, i := range order[n/2:] { // second run: the other half (merged with the existing table)
		m.Record(g(i+1), g(i+100000))
	}
	m.Record(g(order[0]+1), g(777777)) // a second target key for an existing source
	m.Close()

	loaded, _ := Load(path, hdr)
	defer loaded.Close()
	if loaded.Len() != n+1 {
		t.Fatalf("len=%d, want %d", loaded.Len(), n+1)
	}
	for i := 0; i < n; i++ {
		want := []Key{g(i + 100000)}
		if i == order[0] {
			want = append(want, g(777777))
		}
		if got := loaded.Targets(g(i + 1)); !slices.Equal(got, want) {
			t.Fatalf("lookup %d: got %s, want %s", i, got, want)
		}
	}
	if leftovers, _ := filepath.Glob(path + ".*"); len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func TestLeftoverFromAnInterruptedRunIsMergedNextTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.tsv")
	m, _ := Open(path, hdr)
	m.Record(g(1), g(101))
	m.deltaOut.Flush() // simulate ending without Close (crash midway; the lock of a killed process is removed by hand)
	m.delta.Close()
	m.unlock()

	m2, err := Open(path, hdr)
	if err != nil {
		t.Fatal(err)
	}
	m2.Close()
	loaded, _ := Load(path, hdr)
	defer loaded.Close()
	if got := loaded.Targets(g(1)); !slices.Equal(got, []Key{g(101)}) {
		t.Fatalf("pair recorded by the interrupted run was lost: %s", got)
	}
}

func TestMapOfAnotherSourceIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.tsv")
	m, _ := Open(path, hdr)
	m.Record(g(1), g(2))
	m.Close()
	other := hdr
	other.SourceRoot = g(0xcc) // a different source directory
	if _, err := Load(path, other); !errors.Is(err, ErrHeaderMismatch) {
		t.Fatalf("Load: %v", err)
	}
	if _, err := Open(path, other); !errors.Is(err, ErrHeaderMismatch) {
		t.Fatalf("Open must not overwrite another source's map: %v", err)
	}
	if _, err := os.Stat(path + lockSuffix); !os.IsNotExist(err) {
		t.Fatalf("a refused Open must not leave its lock behind: %v", err)
	}
}

// Two clones (into two instances) must not rewrite the table at once; the second one is refused, and can run after.
func TestASecondCloneIsRefusedWhileTheFirstHoldsTheLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.tsv")
	first, err := Open(path, hdr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, hdr); !errors.Is(err, ErrInUse) || !strings.Contains(err.Error(), fmt.Sprintf("pid %d", os.Getpid())) {
		t.Fatalf("a second clone must be refused, naming the holder: %v", err)
	}
	first.Record(g(1), g(101))
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(path, hdr)
	if err != nil {
		t.Fatalf("Close must release the lock: %v", err)
	}
	second.Close()
	reader, err := Load(path, hdr) // diff takes no lock
	if err != nil {
		t.Fatal(err)
	}
	reader.Close()
	if _, err := os.Stat(path + lockSuffix); !os.IsNotExist(err) {
		t.Fatalf("lock left behind: %v", err)
	}
}

func TestMissingFileIsNotExist(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "none"), hdr); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestCorruptSizeIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.tsv")
	m, _ := Open(path, hdr)
	m.Record(g(1), g(2))
	m.Close()
	raw, _ := os.ReadFile(path)
	os.WriteFile(path, bytes.TrimSuffix(raw, []byte("\n")), 0o600) // table one byte short
	if _, err := Load(path, hdr); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("got %v", err)
	}
}

func TestZeroKeysAreNotRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.tsv")
	m, _ := Open(path, hdr)
	m.Record(Key{}, g(1))
	m.Record(g(1), Key{})
	m.Close()
	loaded, _ := Load(path, hdr)
	defer loaded.Close()
	if loaded.Len() != 0 {
		t.Fatalf("an object without an identifier must not be recorded: len=%d", loaded.Len())
	}
}

// A file of an older version, or for another scheme, is refused instead of being misread.
func TestOldFormatAndOtherSchemeAreRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.tsv")
	for _, old := range []string{
		"# ldap-cronin guid-map v3 source-domain=aa target-domain=bb base_dn=x\n",
		"# ldap-cronin mapping v4 scheme=objectGUID source-root=aa target-root=bb base_dn=x\n",
	} {
		os.WriteFile(path, []byte(old), 0o600)
		if _, err := Load(path, hdr); !errors.Is(err, ErrOldFormat) {
			t.Fatalf("an old file must be reported as such: %q %v", old, err)
		}
	}
	if _, err := Open(path, hdr); !errors.Is(err, ErrOldFormat) {
		t.Fatalf("clone must not overwrite an old file silently: %v", err)
	}

	path = filepath.Join(t.TempDir(), "map.tsv")
	m, _ := Open(path, hdr)
	m.Record(g(1), g(2))
	m.Close()
	other := hdr
	other.Scheme = "entryUUID"
	if _, err := Load(path, other); !errors.Is(err, ErrHeaderMismatch) {
		t.Fatalf("keys recorded as objectGUID must not be read as entryUUID: %v", err)
	}
}

func TestRootKeyIdentifiesTheDirectoryWhateverTheURL(t *testing.T) {
	d := fakedir.New()
	d.Put("DC=ad,DC=example,DC=com", map[string][]string{"objectClass": {"domainDNS"}})
	k, err := RootKey(context.Background(), d, "DC=ad,DC=example,DC=com", ObjectGUID)
	if err != nil || k.IsZero() {
		t.Fatalf("%s %v", k, err)
	}
	again, _ := RootKey(context.Background(), d, "DC=ad,DC=example,DC=com", ObjectGUID)
	if again != k {
		t.Fatal("the same directory must give the same key")
	}
	other := fakedir.New()
	other.Put("DC=pad", map[string][]string{}) // bump the counter so the next object gets another identifier
	other.Put("DC=ad,DC=example,DC=com", map[string][]string{"objectClass": {"domainDNS"}})
	if ok, _ := RootKey(context.Background(), other, "DC=ad,DC=example,DC=com", ObjectGUID); ok == k {
		t.Fatal("another directory must give another key")
	}
	if _, err := RootKey(context.Background(), fakedir.New(), "DC=missing,DC=test", ObjectGUID); err == nil {
		t.Fatal("a missing root must be an error")
	}
}

// Each scheme parses only its own form, and the filter it builds finds the same key again.
func TestSchemesParseTheirOwnFormAndShareTheKeySpace(t *testing.T) {
	raw := string([]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	text := "12345678-9ABC-def0-1122-334455667788"
	kg, err := ObjectGUID.Key(raw)
	if err != nil {
		t.Fatal(err)
	}
	ku, err := EntryUUID.Key(text)
	if err != nil {
		t.Fatal(err)
	}
	if kg != ku {
		t.Fatalf("16 raw bytes and the same UUID in text must give one key: %s vs %s", kg, ku)
	}
	if f := ObjectGUID.Filter(kg); f != `(objectGUID=\12\34\56\78\9a\bc\de\f0\11\22\33\44\55\66\77\88)` {
		t.Fatal(f)
	}
	if f := EntryUUID.Filter(ku); f != "(entryUUID=12345678-9abc-def0-1122-334455667788)" {
		t.Fatal(f)
	}
	if _, err := ObjectGUID.Key(text); err == nil {
		t.Fatal("objectGUID must not accept text")
	}
	if _, err := EntryUUID.Key(raw); err == nil {
		t.Fatal("entryUUID must not accept raw bytes")
	}
	if k, err := EntryUUID.Key(""); err != nil || !k.IsZero() {
		t.Fatal("an empty value is the zero key")
	}
}

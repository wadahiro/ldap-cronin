package guidmap

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/fakedir"
)

var hdr = Header{SourceDomain: "aa", TargetDomain: "bb", BaseDN: "OU=IDM,DC=x"}

func g(n int) string { return fmt.Sprintf("%032x", n) } // 32 hex digits (GUID notation)

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
	if got, ok := loaded.Target(g(1)); !ok || got != g(101) || loaded.Len() != 2 {
		t.Fatalf("got %q %v len=%d", got, ok, loaded.Len())
	}
	if _, ok := loaded.Target(g(3)); ok {
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

func TestChangedPairReplacesTheOldOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.tsv")
	m, _ := Open(path, hdr)
	m.Record(g(1), g(101))
	m.Close()
	m, _ = Open(path, hdr)
	m.Record(g(1), g(999)) // the target was rebuilt and the GUID changed
	m.Close()
	loaded, _ := Load(path, hdr)
	defer loaded.Close()
	if got, _ := loaded.Target(g(1)); got != g(999) || loaded.Len() != 1 {
		t.Fatalf("got %q len=%d", got, loaded.Len())
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
	for _, i := range order[:n/2] { // first run: half
		m.Record(g(i), g(i+100000))
	}
	m.Close()
	m, _ = Open(path, hdr)
	for _, i := range order[n/2:] { // second run: the other half (merged with the existing table)
		m.Record(g(i), g(i+100000))
	}
	m.Record(g(order[0]), g(777777)) // overwrite an existing entry
	m.Close()

	loaded, _ := Load(path, hdr)
	defer loaded.Close()
	if loaded.Len() != n {
		t.Fatalf("len=%d, want %d", loaded.Len(), n)
	}
	for i := 0; i < n; i++ {
		want := g(i + 100000)
		if i == order[0] {
			want = g(777777)
		}
		if got, ok := loaded.Target(g(i)); !ok || got != want {
			t.Fatalf("lookup %d: got %q %v, want %q", i, got, ok, want)
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
	m.deltaOut.Flush() // simulate ending without Close (crash midway)
	m.delta.Close()

	m2, err := Open(path, hdr)
	if err != nil {
		t.Fatal(err)
	}
	m2.Close()
	loaded, _ := Load(path, hdr)
	defer loaded.Close()
	if got, ok := loaded.Target(g(1)); !ok || got != g(101) {
		t.Fatalf("pair recorded by the interrupted run was lost: %q %v", got, ok)
	}
}

func TestMapOfAnotherSourceTargetPairIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.tsv")
	m, _ := Open(path, hdr)
	m.Record(g(1), g(2))
	m.Close()
	other := hdr
	other.TargetDomain = "cc" // a different domain
	if _, err := Load(path, other); !errors.Is(err, ErrHeaderMismatch) {
		t.Fatalf("Load: %v", err)
	}
	if _, err := Open(path, other); !errors.Is(err, ErrHeaderMismatch) {
		t.Fatalf("Open must not overwrite another pair's map: %v", err)
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

func TestInvalidGUIDLengthIsRejected(t *testing.T) {
	m, _ := Open(filepath.Join(t.TempDir(), "map.tsv"), hdr)
	defer m.Close()
	if err := m.Record("abc", g(1)); err == nil {
		t.Fatal("a GUID that is not 32 hex chars must be rejected (it would break the fixed-length layout)")
	}
}

func TestHexAndFilterValue(t *testing.T) {
	raw := "\x00\x01\xab\xff"
	if Hex(raw) != "0001abff" || FilterValue(Hex(raw)) != `\00\01\ab\ff` || Hex("") != "" {
		t.Fatalf("%q %q", Hex(raw), FilterValue(Hex(raw)))
	}
}

func TestDomainIDIsTheObjectGUIDOfTheDomainRootAndSurvivesAnotherURL(t *testing.T) {
	d := fakedir.New()
	d.Put("DC=ad,DC=example,DC=com", map[string][]string{"objectClass": {"domainDNS"}})
	id, err := DomainID(d, "OU=IDM,OU=Users,DC=ad,DC=example,DC=com") // looks at the domain root of the base DN
	if err != nil || len(id) != 32 {
		t.Fatalf("%q %v", id, err)
	}
	again, _ := DomainID(d, "OU=Other,DC=ad,DC=example,DC=com")
	if again != id {
		t.Fatal("the same domain must have the same identity whatever the base DN")
	}

	other := fakedir.New()
	other.Put("DC=ad,DC=example,DC=com", map[string][]string{"objectClass": {"domainDNS"}})
	other.Put("DC=pad", map[string][]string{}) // bump the GUID to make it a different domain
	otherID, _ := DomainID(other, "OU=IDM,DC=ad,DC=example,DC=com")
	if otherID == "" {
		t.Fatal("no id")
	}

	if _, err := DomainID(fakedir.New(), "OU=IDM,DC=missing,DC=test"); err == nil {
		t.Fatal("a missing domain root must be an error")
	}
}

func TestTextUUIDAndRawGUIDShareTheSameKey(t *testing.T) {
	raw := string([]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	text := "12345678-9abc-def0-1122-334455667788"
	if Hex(text) != Hex(raw) {
		t.Fatalf("entryUUID text and 16 raw bytes must give one key: %s vs %s", Hex(text), Hex(raw))
	}
	if UUIDText(Hex(text)) != text {
		t.Fatalf("UUIDText must invert Hex for search filters: %s", UUIDText(Hex(text)))
	}
	if Hex("not-a-uuid") == "" || Hex("") != "" {
		t.Fatal("other values keep the plain hex form; empty stays empty")
	}
}

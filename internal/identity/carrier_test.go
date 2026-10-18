package identity

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

func TestMarkerRoundTripsAndTellsOtherSourcesApart(t *testing.T) {
	m := NewMarker("adminDisplayName", Key{0xab, 0xcd, 0xef, 0x01})
	k := Key{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	v := m.Encode(k)
	if len(v) != MarkerLen || v != "ldap-cronin:abcdef01:0102030405060708090a0b0c0d0e0f10" {
		t.Fatalf("%q (%d)", v, len(v))
	}
	if got, err := m.Decode(strings.ToUpper(v)); err != nil || got != k {
		t.Fatalf("matching ignores case on AD, so must Decode: %v %v", got, err)
	}
	other := NewMarker("adminDisplayName", Key{0x99})
	if _, err := other.Decode(v); !errors.Is(err, ErrForeign) {
		t.Fatalf("got %v", err)
	}
	for _, bad := range []string{"", "Shown in the admin tools", "ldap-cronin:abcdef01:zz02030405060708090a0b0c0d0e0f10", v + "0"} {
		if _, err := m.Decode(bad); !errors.Is(err, ErrNotMarker) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	if m.Filter(k) != "(adminDisplayName="+v+")" {
		t.Fatal(m.Filter(k))
	}
}

func TestByMarkerSaysWhenAnEntryCarriesNothing(t *testing.T) {
	m := NewMarker("adminDisplayName", Key{1})
	r := ByMarker(m)
	k := Key{7}
	entry := func(v ...string) directory.Entry {
		return directory.Entry{DN: "CN=x", Attrs: map[string][]string{"adminDisplayName": v}}
	}
	for name, c := range map[string]struct {
		e           directory.Entry
		same, known bool
	}{
		"own":        {entry(m.Encode(k)), true, true},
		"another":    {entry(m.Encode(Key{8})), false, true},
		"foreign":    {entry(NewMarker("adminDisplayName", Key{2}).Encode(k)), false, true},
		"missing":    {entry(), false, false},
		"not marker": {entry("written by an admin"), false, false},
	} {
		same, known, err := r.Same(k, c.e)
		if err != nil || same != c.same || known != c.known {
			t.Errorf("%s: same=%v known=%v %v", name, same, known, err)
		}
	}
}

// A mapping file may record several target keys for one source; any of them is the source's object.
func TestByMapAcceptsAnyRecordedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.tsv")
	m, _ := Open(path, hdr)
	m.Record(g(1), g(101))
	m.Record(g(1), g(102))
	m.Record(g(2), g(201))
	m.Close()
	loaded, err := Load(path, hdr)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	r := ByMap(loaded, ObjectGUID)
	entry := func(k Key) directory.Entry {
		return directory.Entry{DN: "CN=x", Attrs: map[string][]string{"objectGUID": {string(k[:])}}}
	}
	for name, c := range map[string]struct {
		source Key
		e      directory.Entry
		same   bool
	}{
		"first key":     {g(1), entry(g(101)), true},
		"second key":    {g(1), entry(g(102)), true},
		"unrecorded":    {g(1), entry(g(999)), false},
		"another's key": {g(1), entry(g(201)), false},
		"unknown":       {g(3), entry(g(999)), true},
	} {
		same, known, err := r.Same(c.source, c.e)
		if err != nil || same != c.same || !known {
			t.Errorf("%s: same=%v known=%v %v", name, same, known, err)
		}
	}
	if f, ok := r.Filter(g(1)); !ok || f != "(|"+ObjectGUID.Filter(g(101))+ObjectGUID.Filter(g(102))+")" {
		t.Errorf("two keys: %q", f)
	}
	if f, ok := r.Filter(g(2)); !ok || f != ObjectGUID.Filter(g(201)) {
		t.Errorf("one key: %q", f)
	}
	if _, ok := r.Filter(g(3)); ok {
		t.Error("an unknown source has no filter")
	}
}

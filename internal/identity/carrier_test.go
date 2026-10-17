package identity

import (
	"errors"
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

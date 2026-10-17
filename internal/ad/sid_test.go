package ad

import (
	"bytes"
	"testing"
)

// Bytes read back over LDAP from a real Samba after creating an object with GUID 12345678-1234-4234-8234-1234567890ab.
var knownGUID = []byte{0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x34, 0x42, 0x82, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}

func TestGUIDTextUsesLittleEndianForTheFirstThreeFields(t *testing.T) {
	got, err := GUIDText(knownGUID)
	if err != nil || got != "12345678-1234-4234-8234-1234567890ab" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestGUIDRawIsTheInverse(t *testing.T) {
	raw, err := GUIDRaw("12345678-1234-4234-8234-1234567890ab")
	if err != nil || !bytes.Equal(raw, knownGUID) {
		t.Fatalf("%x %v", raw, err)
	}
	for _, bad := range []string{"", "1234", "12345678-1234-4234-8234-1234567890a", "zzzzzzzz-1234-4234-8234-1234567890ab", "12345678-1234-4234-8234-1234567890abc"} {
		if _, err := GUIDRaw(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	if _, err := GUIDText(knownGUID[:15]); err == nil {
		t.Fatal("a short GUID must be rejected")
	}
}

func TestSIDText(t *testing.T) {
	// S-1-5-21-1111111111-2222222222-3333333333-500
	raw := []byte{1, 5, 0, 0, 0, 0, 0, 5,
		21, 0, 0, 0, 0xc7, 0x35, 0x3a, 0x42, 0x8e, 0x6b, 0x74, 0x84, 0x55, 0xa1, 0xae, 0xc6, 0xf4, 0x01, 0x00, 0x00}
	got, err := SIDText(raw)
	if err != nil || got != "S-1-5-21-1111111111-2222222222-3333333333-500" {
		t.Fatalf("%q %v", got, err)
	}
	domain, rid, err := SplitRID(got)
	if err != nil || domain != "S-1-5-21-1111111111-2222222222-3333333333" || rid != 500 {
		t.Fatalf("%q %d %v", domain, rid, err)
	}
	if _, err := SIDText(raw[:10]); err == nil {
		t.Fatal("a truncated SID must be rejected")
	}
	if _, _, err := SplitRID("nonsense"); err == nil {
		t.Fatal("must fail")
	}
}

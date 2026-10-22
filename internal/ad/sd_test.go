package ad

import (
	"encoding/binary"
	"testing"
)

// sid encodes S-1-<authority>-<subs...> in binary.
func sidBytes(authority byte, subs ...uint32) []byte {
	b := []byte{1, byte(len(subs)), 0, 0, 0, 0, 0, authority}
	for _, s := range subs {
		b = binary.LittleEndian.AppendUint32(b, s)
	}
	return b
}

func ace(typ, flags byte, mask uint32, body ...[]byte) []byte {
	var rest []byte
	for _, b := range body {
		rest = append(rest, b...)
	}
	b := []byte{typ, flags, 0, 0}
	b = binary.LittleEndian.AppendUint32(b, mask)
	b = append(b, rest...)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

// selfRelative builds a descriptor of owner, group and the ACEs of its DACL.
func selfRelative(control uint16, owner, group []byte, aces ...[]byte) []byte {
	acl := []byte{2, 0, 0, 0, 0, 0, 0, 0}
	for _, a := range aces {
		acl = append(acl, a...)
	}
	binary.LittleEndian.PutUint16(acl[2:], uint16(len(acl)))
	binary.LittleEndian.PutUint16(acl[4:], uint16(len(aces)))
	b := make([]byte, 20)
	b[0] = 1
	binary.LittleEndian.PutUint16(b[2:], control|0x8004) // self-relative, DACL present
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	b = append(b, owner...)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(b)))
	b = append(b, group...)
	binary.LittleEndian.PutUint32(b[16:], uint32(len(b)))
	return append(b, acl...)
}

// The owner, the group, the protected flag and the explicit ACEs, in order; the inherited ones are each server's.
func TestExplicitSDLeavesOutTheInheritedACEs(t *testing.T) {
	admins, auth := sidBytes(5, 32, 544), sidBytes(5, 11)
	guid := []byte{0x14, 0xcc, 0x28, 0x48, 0x37, 0x14, 0xbc, 0x45, 0x9b, 0x07, 0xad, 0x6f, 0x01, 0x5e, 0x5f, 0x28}
	object := append(binary.LittleEndian.AppendUint32(nil, objectTypePresent), guid...)
	raw := selfRelative(sdControlDACLProtected, admins, admins,
		ace(0, 0x02, 0x10, auth),           // allow read property, inherited by containers
		ace(1, 0x00, 0x20, sidBytes(1, 0)), // deny write property to Everyone
		ace(5, 0x00, 0x3, object, admins),  // an object ACE
		ace(0, 0x12, 0xf01ff, admins),      // inherited: left out
	)
	got, err := ExplicitSD(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := "O:S-1-5-32-544 G:S-1-5-32-544 protected (0;0x02;0x10;S-1-5-11) (1;0x00;0x20;S-1-1-0) (5;0x00;0x3;4828cc14-1437-45bc-9b07-ad6f015e5f28;;S-1-5-32-544)"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	inheritedOnly := selfRelative(0, admins, admins, ace(0, 0x12, 0xf01ff, admins))
	if s, _ := ExplicitSD(inheritedOnly); s != "O:S-1-5-32-544 G:S-1-5-32-544" {
		t.Fatalf("only inherited ACEs: %q", s)
	}
	if _, err := ExplicitSD([]byte{1, 0, 0}); err == nil {
		t.Fatal("a short value is refused")
	}
}

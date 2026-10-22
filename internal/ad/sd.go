package ad

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// A security descriptor (nTSecurityDescriptor) in its self-relative form (MS-DTYP 2.4.6). Of it, what a client
// gives an object is its owner, its group, whether its DACL inherits (the protected flag) and the ACEs it holds
// itself; the inherited ACEs are each server's, computed from the object's parents. ExplicitSD is that part, as
// text, so two servers' descriptors of the same object compare equal when they agree on it.

const (
	sdControlDACLProtected     = 0x1000
	sdControlDACLAutoInherited = 0x0400
	aceFlagInherited           = 0x10
	objectTypePresent          = 0x1
	inheritedObjectTypePresent = 0x2
)

// ExplicitSD renders the owner, the group, the protected flag and the explicit ACEs of the DACL of raw, in order.
func ExplicitSD(raw []byte) (string, error) {
	parts, err := ExplicitSDParts(raw)
	if err != nil {
		return "", err
	}
	out := parts[0]
	for _, a := range parts[1:] {
		out += " (" + a + ")"
	}
	return out, nil
}

// ExplicitSDParts is ExplicitSD as its owner, group and protected flag, then one value per explicit ACE.
func ExplicitSDParts(raw []byte) ([]string, error) {
	if len(raw) < 20 || raw[0] != 1 {
		return nil, fmt.Errorf("not a self-relative security descriptor (%d bytes)", len(raw))
	}
	control := binary.LittleEndian.Uint16(raw[2:])
	owner, group, dacl := binary.LittleEndian.Uint32(raw[4:]), binary.LittleEndian.Uint32(raw[8:]), binary.LittleEndian.Uint32(raw[16:])
	var b strings.Builder
	sid := func(off uint32) string {
		if off == 0 {
			return "-"
		}
		s, _, err := sidAt(raw, int(off))
		if err != nil {
			return "(" + err.Error() + ")"
		}
		return s
	}
	fmt.Fprintf(&b, "O:%s G:%s", sid(owner), sid(group))
	if control&sdControlDACLProtected != 0 {
		b.WriteString(" protected")
	}
	if dacl == 0 {
		b.WriteString(" D:none")
		return []string{b.String()}, nil
	}
	if int(dacl)+8 > len(raw) {
		return nil, fmt.Errorf("DACL offset %d beyond %d bytes", dacl, len(raw))
	}
	parts := []string{b.String()}
	count := int(binary.LittleEndian.Uint16(raw[dacl+4:]))
	at := int(dacl) + 8
	for i := 0; i < count; i++ {
		if at+4 > len(raw) {
			return nil, fmt.Errorf("ACE %d beyond %d bytes", i, len(raw))
		}
		typ, flags, size := raw[at], raw[at+1], int(binary.LittleEndian.Uint16(raw[at+2:]))
		if size < 8 || at+size > len(raw) {
			return nil, fmt.Errorf("ACE %d of size %d", i, size)
		}
		ace := raw[at : at+size]
		at += size
		if flags&aceFlagInherited != 0 {
			continue
		}
		parts = append(parts, aceText(typ, flags, ace))
	}
	return parts, nil
}

// aceText is one ACE: type, flags, access mask, object types and trustee.
func aceText(typ, flags byte, ace []byte) string {
	mask := binary.LittleEndian.Uint32(ace[4:])
	parts := []string{fmt.Sprintf("%d", typ), fmt.Sprintf("0x%02x", flags), fmt.Sprintf("0x%x", mask)}
	at := 8
	switch typ {
	case 5, 6, 7, 8: // the object ACEs
		if len(ace) < 12 {
			return strings.Join(parts, ";") + ";(short)"
		}
		present := binary.LittleEndian.Uint32(ace[8:])
		at = 12
		for _, bit := range []uint32{objectTypePresent, inheritedObjectTypePresent} {
			g := ""
			if present&bit != 0 && at+16 <= len(ace) {
				g, _ = GUIDText(ace[at : at+16])
				at += 16
			}
			parts = append(parts, g)
		}
	}
	s, _, err := sidAt(ace, at)
	if err != nil {
		s = fmt.Sprintf("%x", ace[at:])
	}
	return strings.Join(append(parts, s), ";")
}

// sidAt reads the SID at off of b, and its length.
func sidAt(b []byte, off int) (string, int, error) {
	if off+8 > len(b) {
		return "", 0, fmt.Errorf("SID beyond %d bytes", len(b))
	}
	n := 8 + 4*int(b[off+1])
	if off+n > len(b) {
		return "", 0, fmt.Errorf("SID beyond %d bytes", len(b))
	}
	s, err := SIDText(b[off : off+n])
	return s, n, err
}

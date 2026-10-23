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

const (
	sdControlSelfRelative = 0x8000
	sdControlDACLPresent  = 0x0004
	// The control bits that say something of the SACL, which is never read (the SD flags ask for the owner, the
	// group and the DACL only), so a rewritten descriptor claims none.
	sdControlSACLBits = 0x0010 | 0x0020 | 0x0800 | 0x2000 | 0x0200
	aclRevision       = 2
	aclRevisionDS     = 4 // an ACL holding object ACEs
)

// ExplicitOnly rebuilds raw for writing to another server: the owner, the group, the protected flag and the explicit
// ACEs of the DACL, each SID passed through to (a SID in text form; an error stops). The inherited ACEs are left out:
// the server computes them from the object's parents, and one written by a client stays as an explicit ACE (Samba
// 4.19.5 clears the inherited flag). An owner or group to gives "" for is fallback's (the target object's own,
// nothing when fallback is empty); an ACE whose trustee to gives "" for is left out, and its SID is in dropped.
// An ACE of a type whose layout is not known here is kept as it is.
func ExplicitOnly(raw, fallback []byte, to func(sid string) (string, error)) (out []byte, dropped []string, err error) {
	src, err := parseSD(raw)
	if err != nil {
		return nil, nil, err
	}
	var fb sd
	if len(fallback) > 0 {
		if fb, err = parseSD(fallback); err != nil {
			return nil, nil, fmt.Errorf("the target's: %w", err)
		}
	}
	owner, err := translateSID(src.owner, fb.owner, to)
	if err != nil {
		return nil, nil, err
	}
	group, err := translateSID(src.group, fb.group, to)
	if err != nil {
		return nil, nil, err
	}
	var aces [][]byte
	objects := false
	for _, a := range src.aces {
		if a[1]&aceFlagInherited != 0 {
			continue
		}
		at, ok := sidOffset(a)
		if !ok {
			aces = append(aces, a)
			continue
		}
		text, n, err := sidAt(a, at)
		if err != nil {
			return nil, nil, fmt.Errorf("ACE of type %d: %w", a[0], err)
		}
		mapped, err := to(text)
		if err != nil {
			return nil, nil, err
		}
		if mapped == "" {
			dropped = append(dropped, text)
			continue
		}
		sid, err := SIDRaw(mapped)
		if err != nil {
			return nil, nil, err
		}
		rebuilt := append(append(append([]byte(nil), a[:at]...), sid...), a[at+n:]...)
		binary.LittleEndian.PutUint16(rebuilt[2:], uint16(len(rebuilt)))
		aces = append(aces, rebuilt)
		objects = objects || isObjectACE(a[0])
	}

	control := src.control&^sdControlSACLBits | sdControlSelfRelative
	b := make([]byte, 20)
	b[0] = 1
	if owner != nil {
		binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
		b = append(b, owner...)
	}
	if group != nil {
		binary.LittleEndian.PutUint32(b[8:], uint32(len(b)))
		b = append(b, group...)
	}
	if src.daclPresent {
		control |= sdControlDACLPresent
		binary.LittleEndian.PutUint32(b[16:], uint32(len(b)))
		rev := byte(aclRevision)
		if objects {
			rev = aclRevisionDS
		}
		acl := []byte{rev, 0, 0, 0, 0, 0, 0, 0}
		for _, a := range aces {
			acl = append(acl, a...)
		}
		binary.LittleEndian.PutUint16(acl[2:], uint16(len(acl)))
		binary.LittleEndian.PutUint16(acl[4:], uint16(len(aces)))
		b = append(b, acl...)
	} else {
		control &^= sdControlDACLPresent
	}
	binary.LittleEndian.PutUint16(b[2:], control)
	return b, dropped, nil
}

// sd is a self-relative descriptor taken apart: its control, its owner and group SIDs (nil when absent) and the
// ACEs of its DACL, each as it is.
type sd struct {
	control      uint16
	owner, group []byte
	daclPresent  bool
	aces         [][]byte
}

func parseSD(raw []byte) (sd, error) {
	var out sd
	if len(raw) < 20 || raw[0] != 1 {
		return out, fmt.Errorf("not a self-relative security descriptor (%d bytes)", len(raw))
	}
	out.control = binary.LittleEndian.Uint16(raw[2:])
	for _, f := range []struct {
		at  int
		sid *[]byte
	}{{4, &out.owner}, {8, &out.group}} {
		off := int(binary.LittleEndian.Uint32(raw[f.at:]))
		if off == 0 {
			continue
		}
		_, n, err := sidAt(raw, off)
		if err != nil {
			return out, err
		}
		*f.sid = raw[off : off+n]
	}
	dacl := int(binary.LittleEndian.Uint32(raw[16:]))
	if dacl == 0 || out.control&sdControlDACLPresent == 0 {
		return out, nil
	}
	out.daclPresent = true
	if dacl+8 > len(raw) {
		return out, fmt.Errorf("DACL offset %d beyond %d bytes", dacl, len(raw))
	}
	count := int(binary.LittleEndian.Uint16(raw[dacl+4:]))
	at := dacl + 8
	for i := 0; i < count; i++ {
		if at+4 > len(raw) {
			return out, fmt.Errorf("ACE %d beyond %d bytes", i, len(raw))
		}
		size := int(binary.LittleEndian.Uint16(raw[at+2:]))
		if size < 8 || at+size > len(raw) {
			return out, fmt.Errorf("ACE %d of size %d", i, size)
		}
		out.aces = append(out.aces, raw[at:at+size])
		at += size
	}
	return out, nil
}

// translateSID passes a binary SID through to; "" from it gives fallback.
func translateSID(sid, fallback []byte, to func(string) (string, error)) ([]byte, error) {
	if sid == nil {
		return fallback, nil
	}
	text, err := SIDText(sid)
	if err != nil {
		return nil, err
	}
	mapped, err := to(text)
	if err != nil || mapped == "" {
		return fallback, err
	}
	return SIDRaw(mapped)
}

// isObjectACE reports the ACE types that carry object types before their SID (MS-DTYP 2.4.4.1): allowed, denied,
// audit and alarm object ACEs, and their callback forms.
func isObjectACE(typ byte) bool {
	switch typ {
	case 0x05, 0x06, 0x07, 0x08, 0x0b, 0x0c, 0x0f, 0x10:
		return true
	}
	return false
}

// sidOffset is where the SID of ace starts; false for a type whose layout is not known here.
func sidOffset(ace []byte) (int, bool) {
	switch typ := ace[0]; {
	case isObjectACE(typ):
		if len(ace) < 12 {
			return 0, false
		}
		at := 12
		present := binary.LittleEndian.Uint32(ace[8:])
		for _, bit := range []uint32{objectTypePresent, inheritedObjectTypePresent} {
			if present&bit != 0 {
				at += 16
			}
		}
		return at, true
	case typ <= 0x03, typ == 0x09, typ == 0x0a, typ == 0x0d, typ == 0x0e, typ == 0x11, typ == 0x13:
		return 8, true
	}
	return 0, false
}

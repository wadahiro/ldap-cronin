// Package ad holds what only Active Directory (and Samba AD) has: the binary objectGUID and objectSid forms and the
// domain identity read from the root and the configuration partition. Nothing outside AD-only features uses it.
//
// sid.go converts AD objectGUID and objectSid (binary as returned over LDAP) to and from their text notation.
package ad

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// GUIDText formats a 16-byte objectGUID as "12345678-1234-4234-8234-1234567890ab".
// The first three fields are little-endian and the last two keep their byte order (the Windows GUID storage format).
func GUIDText(raw []byte) (string, error) {
	if len(raw) != 16 {
		return "", fmt.Errorf("objectGUID must be 16 bytes, got %d", len(raw))
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(raw[0:4]), binary.LittleEndian.Uint16(raw[4:6]), binary.LittleEndian.Uint16(raw[6:8]),
		raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]), nil
}

// GUIDRaw is the inverse of GUIDText (text to the binary form used over LDAP).
func GUIDRaw(text string) ([]byte, error) {
	parts := strings.Split(text, "-")
	if len(parts) != 5 || len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		return nil, fmt.Errorf("invalid GUID format: %q", text)
	}
	var out [16]byte
	d1, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid GUID format: %q", text)
	}
	d2, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid GUID format: %q", text)
	}
	d3, err := strconv.ParseUint(parts[2], 16, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid GUID format: %q", text)
	}
	binary.LittleEndian.PutUint32(out[0:4], uint32(d1))
	binary.LittleEndian.PutUint16(out[4:6], uint16(d2))
	binary.LittleEndian.PutUint16(out[6:8], uint16(d3))
	tail := parts[3] + parts[4]
	for i := 0; i < 8; i++ {
		b, err := strconv.ParseUint(tail[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid GUID format: %q", text)
		}
		out[8+i] = byte(b)
	}
	return out[:], nil
}

// SIDText formats a binary objectSid as "S-1-5-21-…-500".
func SIDText(raw []byte) (string, error) {
	if len(raw) < 8 {
		return "", fmt.Errorf("objectSid is too short (%d bytes)", len(raw))
	}
	count := int(raw[1])
	if len(raw) != 8+4*count {
		return "", fmt.Errorf("objectSid length mismatch (%d bytes for %d sub-authorities)", len(raw), count)
	}
	var authority uint64
	for _, b := range raw[2:8] {
		authority = authority<<8 | uint64(b)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", raw[0], authority)
	for i := 0; i < count; i++ {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(raw[8+4*i:]))
	}
	return sb.String(), nil
}

// SplitRID splits a SID into the domain part and the trailing RID.
func SplitRID(sid string) (domain string, rid int, err error) {
	i := strings.LastIndex(sid, "-")
	if i < 0 {
		return "", 0, fmt.Errorf("invalid SID format: %q", sid)
	}
	rid, err = strconv.Atoi(sid[i+1:])
	if err != nil {
		return "", 0, fmt.Errorf("invalid SID format: %q", sid)
	}
	return sid[:i], rid, nil
}

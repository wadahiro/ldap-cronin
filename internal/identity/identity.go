// Package identity is the one place that knows how a directory identifies an object across renames and moves
// (objectGUID on AD, entryUUID elsewhere), and the local mapping between source and target identifiers.
//
// Both identifiers are 16 bytes. AD returns objectGUID as raw bytes, generic servers return entryUUID as text;
// each Scheme parses only its own form into a Key, so the mapping file and the matching logic never guess.
package identity

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// Key is an object identifier in a form independent of the server type. The zero Key means "none".
type Key [16]byte

func (k Key) IsZero() bool { return k == Key{} }

// String is the 32 lowercase hex digits used in the mapping file.
func (k Key) String() string { return hex.EncodeToString(k[:]) }

// ParseHex is the inverse of String.
func ParseHex(s string) (Key, error) {
	var k Key
	if len(s) != 32 {
		return k, fmt.Errorf("identifier %q is not 32 hex digits", s)
	}
	if _, err := hex.Decode(k[:], []byte(s)); err != nil {
		return k, fmt.Errorf("identifier %q is not 32 hex digits", s)
	}
	return k, nil
}

// Scheme is how one kind of server identifies objects.
type Scheme interface {
	// Attr is the identifier attribute (objectGUID, entryUUID). It is server-assigned and never copied.
	Attr() string
	// Key parses a value of Attr as returned by the server. An empty value is the zero Key without error.
	Key(value string) (Key, error)
	// Filter is a search filter matching the object with key k.
	Filter(k Key) string
	// CarryOver lists the attributes a native import keeps from the source (nil where there is no native import).
	CarryOver() []string
}

// ObjectGUID is the AD scheme: objectGUID, 16 raw bytes.
var ObjectGUID Scheme = guidScheme{}

// EntryUUID is the RFC 4530 scheme of generic servers: entryUUID, text "8-4-4-4-12".
var EntryUUID Scheme = uuidScheme{}

type guidScheme struct{}

func (guidScheme) Attr() string { return "objectGUID" }

func (guidScheme) Key(v string) (Key, error) {
	var k Key
	if v == "" {
		return k, nil
	}
	if len(v) != len(k) {
		return k, fmt.Errorf("objectGUID must be 16 bytes, got %d", len(v))
	}
	copy(k[:], v)
	return k, nil
}

func (guidScheme) Filter(k Key) string {
	var b strings.Builder
	b.WriteString("(objectGUID=")
	for _, c := range k {
		fmt.Fprintf(&b, `\%02x`, c)
	}
	b.WriteString(")")
	return b.String()
}

// CarryOver includes objectSid: a native import that kept only the GUID would give every account a new SID,
// which is what an application keyed on objectSid would notice first.
func (guidScheme) CarryOver() []string { return []string{"objectGUID", "objectSid"} }

type uuidScheme struct{}

func (uuidScheme) Attr() string { return "entryUUID" }

func (uuidScheme) Key(v string) (Key, error) {
	if v == "" {
		return Key{}, nil
	}
	if len(v) != 36 || v[8] != '-' || v[13] != '-' || v[18] != '-' || v[23] != '-' {
		return Key{}, fmt.Errorf("entryUUID %q is not in 8-4-4-4-12 form", v)
	}
	return ParseHex(strings.ToLower(strings.ReplaceAll(v, "-", "")))
}

func (uuidScheme) Filter(k Key) string {
	h := k.String()
	return "(entryUUID=" + h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:] + ")"
}

func (uuidScheme) CarryOver() []string { return nil }

// Lookup maps a source key to the target key of the same object.
type Lookup interface {
	Target(source Key) (Key, bool)
	// Len is the number of known pairs (0 for Identity, which needs none).
	Len() int
	// Preserved is true when target objects carry the source identifiers (a native import), so no mapping is used.
	Preserved() bool
}

// Identity is the mapping "the target key equals the source key", for a native import that kept objectGUID.
type Identity struct{}

func (Identity) Target(source Key) (Key, bool) { return source, !source.IsZero() }
func (Identity) Len() int                      { return 0 }
func (Identity) Preserved() bool               { return true }

// Of returns the key of an entry read with s.Attr(). An entry without the attribute gives the zero Key.
func Of(s Scheme, e directory.Entry) (Key, error) {
	v := e.Values(s.Attr())
	if len(v) == 0 {
		return Key{}, nil
	}
	return s.Key(v[0])
}

// RootKey returns the key of the naming-context root. It identifies the directory itself: the URL changes when a
// lab is rebuilt or started from a snapshot on another port, while the root object, and so its key, stays.
func RootKey(ctx context.Context, d directory.Directory, root string, s Scheme) (Key, error) {
	e, err := d.Get(ctx, root, []string{s.Attr()})
	if err != nil {
		return Key{}, fmt.Errorf("cannot read root %s: %w", root, err)
	}
	if e == nil {
		return Key{}, fmt.Errorf("root %s not found", root)
	}
	k, err := Of(s, *e)
	if err != nil {
		return Key{}, fmt.Errorf("root %s: %w", root, err)
	}
	if k.IsZero() {
		return Key{}, fmt.Errorf("root %s has no %s", root, s.Attr())
	}
	return k, nil
}

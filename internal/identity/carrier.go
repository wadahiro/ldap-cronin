package identity

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

const markerPrefix = "ldap-cronin:"

// MarkerLen is the length of every marker value: the prefix, 8 hex digits of the source root key, a colon and the
// 32 hex digits of the source key. A marker attribute must hold at least this many characters.
const MarkerLen = len(markerPrefix) + 8 + 1 + 32

// ErrForeign is returned by Marker.Decode for a marker written by a clone from another source directory.
var ErrForeign = errors.New("marker of another source")

// ErrNotMarker is returned by Marker.Decode for a value this tool did not write.
var ErrNotMarker = errors.New("not a marker")

// Marker is the source key written into an attribute of the target object, for targets that assign their own
// identifiers and let no client set them (AD, Samba over LDAP). The value names the source directory by its root key,
// so a marker left by a clone from another source is told apart without a header anywhere.
type Marker struct {
	Attr   string
	source string // the first 8 hex digits of the source root key
}

// NewMarker returns the marker of objects cloned from the directory whose root has the key sourceRoot.
func NewMarker(attr string, sourceRoot Key) Marker {
	return Marker{Attr: attr, source: sourceRoot.String()[:8]}
}

// Encode is the value written for an object whose source key is k; it is also the assertion value of Filter.
func (m Marker) Encode(k Key) string { return markerPrefix + m.source + ":" + k.String() }

// Decode is the inverse of Encode. Matching on AD ignores case, so Decode does too.
func (m Marker) Decode(v string) (Key, error) {
	v = strings.ToLower(v)
	rest, ok := strings.CutPrefix(v, markerPrefix)
	if !ok || len(v) != MarkerLen || rest[8] != ':' {
		return Key{}, ErrNotMarker
	}
	k, err := ParseHex(rest[9:])
	if err != nil {
		return Key{}, ErrNotMarker
	}
	if rest[:8] != m.source {
		return Key{}, ErrForeign
	}
	return k, nil
}

// Filter matches the target object marked with k. The value has no character that needs escaping.
func (m Marker) Filter(k Key) string { return "(" + m.Attr + "=" + m.Encode(k) + ")" }

// Resolver tells diff whether a target entry is the object cloned from a source object, and how to search for that
// object when it is not at the source DN.
type Resolver interface {
	// Attrs are the attributes to read on target entries.
	Attrs() []string
	// Same reports whether e is the object cloned from the source object with key source. known is false when e
	// carries nothing to tell (a marker missing or not written by this tool); same is then meaningless.
	Same(source Key, e directory.Entry) (same, known bool, err error)
	// Filter matches the target object cloned from source. ok is false when it cannot be searched for.
	Filter(source Key) (filter string, ok bool)
	// Describe says, for the summary, how objects are matched.
	Describe() string
}

// ByIdentity matches objects whose target identifier is the source identifier: after a native import, or an Add
// that kept entryUUID with the relax control.
func ByIdentity(s Scheme) Resolver { return byIdentity{s} }

type byIdentity struct{ s Scheme }

func (r byIdentity) Attrs() []string { return []string{r.s.Attr()} }

func (r byIdentity) Same(source Key, e directory.Entry) (bool, bool, error) {
	k, err := Of(r.s, e)
	if err != nil {
		return false, false, fmt.Errorf("%s on the target: %w", e.DN, err)
	}
	return k.IsZero() || k == source, true, nil
}

func (r byIdentity) Filter(source Key) (string, bool) { return r.s.Filter(source), true }

func (r byIdentity) Describe() string {
	return fmt.Sprintf("%s preserved: the target holds the source's %s", r.s.Attr(), r.s.Attr())
}

// ByMarker matches objects by the marker clone wrote.
func ByMarker(m Marker) Resolver { return byMarker{m} }

type byMarker struct{ m Marker }

func (r byMarker) Attrs() []string { return []string{r.m.Attr} }

func (r byMarker) Same(source Key, e directory.Entry) (bool, bool, error) {
	v := e.Values(r.m.Attr)
	if len(v) == 0 {
		return false, false, nil
	}
	k, err := r.m.Decode(v[0])
	switch {
	case errors.Is(err, ErrNotMarker):
		return false, false, nil
	case errors.Is(err, ErrForeign):
		return false, true, nil // cloned from another source: not this source's object
	}
	return k == source, true, nil
}

func (r byMarker) Filter(source Key) (string, bool) { return r.m.Filter(source), true }

func (r byMarker) Describe() string { return "markers in " + r.m.Attr }

// ByMap matches objects through a mapping file: a target object is the source's when its key is any of the ones
// recorded for it (a restore or another instance holds an earlier clone's). A source object the file does not know
// (added after the clone) is trusted at its DN, as is a target entry without an identifier.
func ByMap(m *Map, s Scheme) Resolver { return byMap{m, s} }

type byMap struct {
	m *Map
	s Scheme
}

func (r byMap) Attrs() []string { return []string{r.s.Attr()} }

func (r byMap) Same(source Key, e directory.Entry) (bool, bool, error) {
	targets := r.m.Targets(source)
	if len(targets) == 0 {
		return true, true, nil
	}
	k, err := Of(r.s, e)
	if err != nil {
		return false, false, fmt.Errorf("%s on the target: %w", e.DN, err)
	}
	return k.IsZero() || slices.Contains(targets, k), true, nil
}

// Filter finds any target object recorded for the source: one filter, or an OR of them when it was cloned again.
func (r byMap) Filter(source Key) (string, bool) {
	targets := r.m.Targets(source)
	if len(targets) == 0 {
		return "", false
	}
	if len(targets) == 1 {
		return r.s.Filter(targets[0]), true
	}
	var b strings.Builder
	b.WriteString("(|")
	for _, k := range targets {
		b.WriteString(r.s.Filter(k))
	}
	b.WriteString(")")
	return b.String(), true
}

func (r byMap) Describe() string {
	return fmt.Sprintf("%d %s pairs in the mapping file", r.m.Len(), r.s.Attr())
}

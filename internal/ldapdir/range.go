package ldapdir

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// DefaultRangeSize matches the AD MaxValRange (1500 by default).
const DefaultRangeSize = 1500

// defaultRanged are the attributes retrieved in ranges unless SetRangedAttrs says otherwise (the AD behavior).
var defaultRanged = map[string]bool{"member": true}

// rangedRequest returns the requested attribute list with member rewritten into ranged form.
// AD splits a large value set into ranges on its own, whereas Samba returns everything at once.
// Always specifying the range explicitly puts both through the same retrieval path.
func rangedRequest(attrs []string, size int) []string {
	return rangedRequestFor(defaultRanged, attrs, size)
}

// rangedRequestFor is rangedRequest for an explicit set of ranged attributes (empty for servers without the range option).
func rangedRequestFor(ranged map[string]bool, attrs []string, size int) []string {
	out := make([]string, len(attrs))
	for i, a := range attrs {
		out[i] = a
		if ranged[strings.ToLower(a)] {
			out[i] = fmt.Sprintf("%s;range=0-%d", a, size-1)
		}
	}
	return out
}

// RangedValues is an attribute returned by one search (with its ranged name) and its values.
type RangedValues struct {
	Name   string
	Values []string
}

// CollectRanges fetches values from index next onward until the open-ended range ("N-*") is returned, and merges them.
// fetch receives an attribute specification of the form "member;range=N-*".
func CollectRanges(attr string, next int, fetch func(spec string) ([]RangedValues, error)) ([]string, error) {
	var out []string
	for {
		got, err := fetch(fmt.Sprintf("%s;range=%d-*", attr, next))
		if err != nil {
			return nil, err
		}
		advanced := false
		for _, g := range got {
			ri, ok := ParseRange(g.Name)
			if !ok || !strings.EqualFold(ri.Base, attr) {
				continue
			}
			out = append(out, g.Values...)
			if ri.Last {
				return out, nil
			}
			next, advanced = ri.High+1, true
		}
		if !advanced {
			// The server returns nothing for an out-of-range request. All values have already been fetched, so stop.
			return out, nil
		}
		if len(out) > maxCollected {
			return nil, errors.New("too many values")
		}
	}
}

// Upper bound to prevent a runaway loop (an AD group is limited to roughly 50,000 members).
const maxCollected = 10_000_000

// RangeInfo is the parsed form of an AD ranged attribute name such as "member;range=0-1499".
type RangeInfo struct {
	Base string
	High int
	Last bool // all values up to the end have been fetched ("0-*")
}

// ParseRange returns the parsed result if the attribute name is in ranged form.
// When a value set exceeds about 1500 values, AD returns it as member;range=0-1499 instead of member.
func ParseRange(name string) (RangeInfo, bool) {
	base, opt, found := strings.Cut(name, ";range=")
	if !found {
		return RangeInfo{}, false
	}
	_, high, found := strings.Cut(opt, "-")
	if !found {
		return RangeInfo{}, false
	}
	if high == "*" {
		return RangeInfo{Base: base, Last: true}, true
	}
	n, err := strconv.Atoi(high)
	if err != nil {
		return RangeInfo{}, false
	}
	return RangeInfo{Base: base, High: n}, true
}

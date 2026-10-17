// Package compare holds the attribute value equivalence shared by clone (deciding whether an update is needed) and
// diff. It knows no attribute names: which normalizer applies to which attribute is decided by plan (DN-valued
// attributes, objectClass) and by the profile (server-specific value semantics).
package compare

import (
	"sort"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/dn"
)

// Normalizer maps a value to the form in which equal values are identical. nil compares values as they are.
type Normalizer func(string) string

// DN absorbs the case and escaping differences of DN values.
var DN Normalizer = dn.Normalize

// CaseIgnore compares values ignoring case (objectClass names).
var CaseIgnore Normalizer = strings.ToLower

func (n Normalizer) apply(v string) string {
	if n == nil {
		return v
	}
	return n(v)
}

// Equal compares two value sets under n. Order is ignored.
func Equal(n Normalizer, a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := normalized(n, a), normalized(n, b)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// EqualDN compares attributes whose values are DNs.
func EqualDN(a, b []string) bool { return Equal(DN, a, b) }

func normalized(n Normalizer, values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = n.apply(v)
	}
	sort.Strings(out)
	return out
}

// SetDiff returns the difference between the value sets a and b in their original notation, compared under n.
// It is used to show, for multi-valued attributes such as member, which side alone holds each value.
func SetDiff(n Normalizer, a, b []string) (onlyA, onlyB []string) {
	inA, inB := make(map[string]bool, len(a)), make(map[string]bool, len(b))
	for _, v := range a {
		inA[n.apply(v)] = true
	}
	for _, v := range b {
		inB[n.apply(v)] = true
	}
	for _, v := range a {
		if !inB[n.apply(v)] {
			onlyA = append(onlyA, v)
		}
	}
	for _, v := range b {
		if !inA[n.apply(v)] {
			onlyB = append(onlyB, v)
		}
	}
	// The order the server returns differs between AD and Samba and can change from run to run, so sort to keep the output stable.
	sortByKey(onlyA, n)
	sortByKey(onlyB, n)
	return onlyA, onlyB
}

// sortByKey orders values by their normalized comparison key. Ties fall back to the original value so the result is deterministic.
func sortByKey(values []string, n Normalizer) {
	sort.SliceStable(values, func(i, j int) bool {
		ki, kj := n.apply(values[i]), n.apply(values[j])
		if ki != kj {
			return ki < kj
		}
		return values[i] < values[j]
	})
}

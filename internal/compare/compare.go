// Package compare holds the attribute value equivalence checks shared by clone (deciding whether an update is needed) and diff.
package compare

import (
	"sort"
	"strconv"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/dn"
)

const (
	uacLockout         = 0x10
	uacPasswordExpired = 0x800000
	// accountExpires "never" has two representations: 0 and 2^63-1.
	neverExpires = "9223372036854775807"
)

// SanitizeUAC drops the bits that cannot be written (the ones the server manages).
func SanitizeUAC(v string) string {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return v
	}
	return strconv.FormatInt(n&^(uacLockout|uacPasswordExpired), 10)
}

// Equal compares two value sets according to the meaning of each attribute. Order is ignored.
func Equal(attr string, a, b []string) bool {
	x, y := normalize(attr, a), normalize(attr, b)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// EqualDN compares attributes whose values are DNs. It absorbs case and escaping differences and ignores order.
func EqualDN(a, b []string) bool {
	x, y := make([]string, len(a)), make([]string, len(b))
	for i, v := range a {
		x[i] = dn.Normalize(v)
	}
	for i, v := range b {
		y[i] = dn.Normalize(v)
	}
	sort.Strings(x)
	sort.Strings(y)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// SetDiff returns the difference between the value sets a and b in their original notation. Attributes in isDN are compared as normalized DNs.
// It is used to show, for multi-valued attributes such as member, which side alone holds each value.
func SetDiff(attr string, isDN bool, a, b []string) (onlyA, onlyB []string) {
	key := func(v string) string {
		if isDN {
			return dn.Normalize(v)
		}
		return normalizeValue(attr, v)
	}
	inA, inB := make(map[string]bool, len(a)), make(map[string]bool, len(b))
	for _, v := range a {
		inA[key(v)] = true
	}
	for _, v := range b {
		inB[key(v)] = true
	}
	for _, v := range a {
		if !inB[key(v)] {
			onlyA = append(onlyA, v)
		}
	}
	for _, v := range b {
		if !inA[key(v)] {
			onlyB = append(onlyB, v)
		}
	}
	// The order the server returns differs between AD and Samba and can change from run to run, so sort to keep the output stable.
	sortByKey(onlyA, key)
	sortByKey(onlyB, key)
	return onlyA, onlyB
}

// sortByKey orders values by their normalized comparison key. Ties fall back to the original value so the result is deterministic.
func sortByKey(values []string, key func(string) string) {
	sort.SliceStable(values, func(i, j int) bool {
		ki, kj := key(values[i]), key(values[j])
		if ki != kj {
			return ki < kj
		}
		return values[i] < values[j]
	})
}

func normalize(attr string, values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = normalizeValue(attr, v)
	}
	sort.Strings(out)
	return out
}

func normalizeValue(attr, v string) string {
	switch strings.ToLower(attr) {
	case "objectclass":
		return strings.ToLower(v)
	case "member", "manager", "managedby":
		return dn.Normalize(v)
	case "useraccountcontrol":
		return SanitizeUAC(v)
	case "accountexpires":
		if v == "0" {
			return neverExpires
		}
	}
	return v
}

// Package attrs holds the logic that decides which attributes to clone.
//
// It is allow-list based rather than exclude-list based, because with an exclude list
// unexpected attributes such as extensionAttribute* would silently land in the target.
package attrs

import (
	"fmt"
	"sort"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/profile"
)

const (
	KindOU    = profile.KindOU
	KindGroup = profile.KindGroup
	KindUser  = profile.KindUser
)

// Kinds are the object kinds that can be cloned.
var Kinds = profile.Kinds

// PasswordAttrs are the AD password-related attribute names (see profile.Profile.PasswordAttrs for other profiles).
// LDAP cannot read them (or must not), so they are neither copied nor compared.
var PasswordAttrs = profile.AD.PasswordAttrs

func lowerSet(names ...string) map[string]bool { return profile.Set(names) }

// Override is an allow-list adjustment that comes from the config file.
type Override struct {
	Include map[string][]string // replaces the defaults per kind
	Extra   []string            // added to the defaults of all kinds
	Exclude []string            // removed from all kinds
}

// Resolve returns the final attribute list per kind for the AD profile.
func Resolve(kind string, o Override) ([]string, error) { return ResolveFor(profile.AD, kind, o) }

// ResolveFor returns the final attribute list per kind for a profile.
func ResolveFor(p profile.Profile, kind string, o Override) ([]string, error) {
	required, alwaysExcluded := p.Required, lowerSet(p.NeverClone...)
	base, ok := p.Defaults[kind]
	if !ok {
		return nil, fmt.Errorf("unknown object kind %q", kind)
	}
	if inc, ok := o.Include[kind]; ok {
		base = inc
	}
	excluded := lowerSet(o.Exclude...)
	seen := map[string]bool{}
	var out []string
	add := func(name string, isRequired bool) error {
		key := strings.ToLower(name)
		if alwaysExcluded[key] {
			return fmt.Errorf("attribute %q cannot be cloned", name)
		}
		if seen[key] || (excluded[key] && !isRequired) {
			return nil
		}
		seen[key] = true
		out = append(out, name)
		return nil
	}
	for _, list := range [][]string{required, base, o.Extra} {
		for _, name := range list {
			if err := add(name, isIn(required, name)); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func isIn(list []string, name string) bool {
	for _, n := range list {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// IsMaskable reports whether name can be replaced by a fixed string under the AD profile.
func IsMaskable(name string) bool { return IsMaskableFor(profile.AD, name) }

// IsMaskableFor reports whether name can be replaced by a fixed string under a profile.
func IsMaskableFor(p profile.Profile, name string) bool {
	return !lowerSet(p.NoMask...)[strings.ToLower(name)]
}

// Defaults returns a copy of the AD default allow list per kind (required attributes are not included).
func Defaults() map[string][]string { return DefaultsFor(profile.AD) }

// DefaultsFor returns a copy of a profile's default allow list per kind (required attributes are not included).
func DefaultsFor(p profile.Profile) map[string][]string {
	out := make(map[string][]string, len(p.Defaults))
	for k, v := range p.Defaults {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// SortedKinds returns kinds ordered as in Kinds (ou, group, user).
func SortedKinds(kinds []string) []string {
	order := map[string]int{}
	for i, k := range Kinds {
		order[k] = i
	}
	out := append([]string(nil), kinds...)
	sort.SliceStable(out, func(i, j int) bool { return order[out[i]] < order[out[j]] })
	return out
}

// Package dn provides structural operations on DN strings.
// Counting commas naively gets escapes such as `CN=Doe\, John` wrong,
// so splitting scans with escapes in mind and normalization for comparison is left to ldap.ParseDN.
package dn

import (
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Split splits a DN into RDN strings, keeping the original notation.
func Split(dn string) []string {
	var rdns []string
	start := 0
	for i := 0; i < len(dn); i++ {
		switch dn[i] {
		case '\\':
			i++
		case ',':
			rdns = append(rdns, dn[start:i])
			start = i + 1
		}
	}
	if strings.TrimSpace(dn) == "" {
		return nil
	}
	return append(rdns, dn[start:])
}

// FirstRDN returns the attribute name and the unescaped value of the first RDN of a DN.
func FirstRDN(dnStr string) (typ, val string, ok bool) {
	parsed, err := ldap.ParseDN(dnStr)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return "", "", false
	}
	a := parsed.RDNs[0].Attributes[0]
	return a.Type, a.Value, true
}

func Depth(dn string) int { return len(Split(dn)) }

// Parent returns the parent DN, or an empty string for the topmost one.
func Parent(dn string) string {
	rdns := Split(dn)
	if len(rdns) <= 1 {
		return ""
	}
	return strings.Join(rdns[1:], ",")
}

// Normalize returns a map key that absorbs case and escaping differences. Values are escaped again in one form, so
// a value holding a comma (`CN=x\,OU=Users`) never reads as two RDNs.
func Normalize(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(dn))
	}
	rdns := make([]string, 0, len(parsed.RDNs))
	for _, rdn := range parsed.RDNs {
		attrs := make([]string, 0, len(rdn.Attributes))
		for _, a := range rdn.Attributes {
			attrs = append(attrs, strings.ToLower(strings.TrimSpace(a.Type))+"="+ldap.EscapeDN(strings.ToLower(a.Value)))
		}
		rdns = append(rdns, strings.Join(attrs, "+"))
	}
	return strings.Join(rdns, ",")
}

func Equal(a, b string) bool { return Normalize(a) == Normalize(b) }

// IsDescendant reports whether dn is a strict descendant of ancestor. RDNs are compared, not string suffixes: a
// value ending in an escaped comma and an RDN (`CN=x\,OU=Users,DC=ad`) is not below OU=Users.
func IsDescendant(dn, ancestor string) bool {
	d, a := Split(Normalize(dn)), Split(Normalize(ancestor))
	if len(a) == 0 || len(d) <= len(a) {
		return false
	}
	return slices.Equal(d[len(d)-len(a):], a)
}

// DomainRoot returns the trailing run of DC= components of a DN (the domain root).
func DomainRoot(dn string) string {
	rdns := Split(dn)
	i := len(rdns)
	for i > 0 && strings.HasPrefix(strings.ToLower(strings.TrimSpace(rdns[i-1])), "dc=") {
		i--
	}
	return strings.Join(rdns[i:], ",")
}

// Ancestors returns the DNs from the parent of dn down to just below domain, nearest first (domain itself is excluded).
func Ancestors(dn, domain string) []string {
	var out []string
	for p := Parent(dn); p != "" && !Equal(p, domain); p = Parent(p) {
		out = append(out, p)
	}
	return out
}

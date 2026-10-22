package dn

import (
	"strconv"
	"strings"
)

// A reference value is a DN (also Object(OR-Name), such as Exchange's authOrig), or a DN inside a larger value: AD's
// DN-Binary (B:<count>:<hex>:<DN>, msDS-RevealedUsers) and DN-String (S:<count>:<string>:<DN>). <count> is the number of hex digits or of
// characters of the middle part, which may itself hold colons. No DN starts with B: or S: (an RDN needs a type and =),
// so the form alone tells them apart.

// SplitRef returns the part of a reference value before its DN (B:<count>:<hex>: or S:<count>:<string>:) and the
// DN. A plain DN, or anything that does not parse as such a value, is all DN: "", v.
func SplitRef(v string) (prefix, dn string) {
	if len(v) < 4 || v[1] != ':' || !strings.ContainsRune("BbSs", rune(v[0])) {
		return "", v
	}
	rest := v[2:]
	colon := strings.IndexByte(rest, ':')
	if colon <= 0 {
		return "", v
	}
	n, err := strconv.Atoi(rest[:colon])
	if err != nil || n < 0 {
		return "", v
	}
	middle := []rune(rest[colon+1:])
	if len(middle) < n+1 || middle[n] != ':' {
		return "", v
	}
	dn = string(middle[n+1:])
	if dn == "" {
		return "", v
	}
	return v[:len(v)-len(dn)], dn
}

// RefDN is the DN of a reference value.
func RefDN(v string) string {
	_, d := SplitRef(v)
	return d
}

// RewrapRef is v naming d instead: its binary or string part kept.
func RewrapRef(v, d string) string {
	prefix, _ := SplitRef(v)
	return prefix + d
}

// NormalizeRef is Normalize for a reference value: the DN normalized, the hex of a DN-Binary value in one case, and
// an empty binary or string part the same as none (B:0::<DN> is <DN>), whichever form a server returns.
func NormalizeRef(v string) string {
	prefix, d := SplitRef(v)
	if prefix == "" {
		return Normalize(d)
	}
	head := strings.ToUpper(prefix[:1])
	parts := strings.SplitN(prefix[2:], ":", 2)
	middle := strings.TrimSuffix(parts[1], ":")
	if middle == "" {
		return Normalize(d)
	}
	if head == "B" {
		middle = strings.ToUpper(middle)
	}
	return head + ":" + parts[0] + ":" + middle + ":" + Normalize(d)
}

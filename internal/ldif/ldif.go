// Package ldif formats LDIF for dry-run.
package ldif

import (
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"strings"
)

// safe reports whether s is an RFC 2849 SAFE-STRING (anything else is base64-encoded).
func safe(v string) bool {
	if v == "" {
		return true
	}
	if v[0] == ' ' || v[0] == ':' || v[0] == '<' || v[len(v)-1] == ' ' {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c == 0 || c == '\n' || c == '\r' || c >= 0x80 {
			return false
		}
	}
	return true
}

func Line(name, value string) string {
	if safe(value) {
		return name + ": " + value
	}
	return name + ":: " + base64.StdEncoding.EncodeToString([]byte(value))
}

// Redacted lists attributes whose values are emitted as a comment instead of being printed.
var redacted = map[string]bool{"unicodepwd": true}

func Attrs(w io.Writer, attrs map[string][]string, prefix string) {
	names := make([]string, 0, len(attrs))
	for n := range attrs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if redacted[strings.ToLower(n)] {
			fmt.Fprintf(w, "# %s: <redacted>\n", n)
			continue
		}
		for _, v := range attrs[n] {
			fmt.Fprintln(w, prefix+Line(n, v))
		}
	}
}

func Add(w io.Writer, dn string, attrs map[string][]string) {
	fmt.Fprintln(w, Line("dn", dn))
	fmt.Fprintln(w, "changetype: add")
	Attrs(w, attrs, "")
	fmt.Fprintln(w)
}

func Replace(w io.Writer, dn string, attrs map[string][]string) {
	fmt.Fprintln(w, Line("dn", dn))
	fmt.Fprintln(w, "changetype: modify")
	names := make([]string, 0, len(attrs))
	for n := range attrs {
		names = append(names, n)
	}
	sort.Strings(names)
	for i, n := range names {
		if i > 0 {
			fmt.Fprintln(w, "-")
		}
		fmt.Fprintf(w, "replace: %s\n", n)
		Attrs(w, map[string][]string{n: attrs[n]}, "")
	}
	fmt.Fprintln(w)
}

func AddValues(w io.Writer, dn, attr string, values []string) {
	fmt.Fprintln(w, Line("dn", dn))
	fmt.Fprintln(w, "changetype: modify")
	fmt.Fprintf(w, "add: %s\n", attr)
	Attrs(w, map[string][]string{attr: values}, "")
	fmt.Fprintln(w)
}

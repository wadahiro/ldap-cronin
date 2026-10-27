// Package ldif formats LDIF for dry-run.
package ldif

import (
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
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

// Writer prints changes as LDIF. Values of the attributes Secret names are printed as a comment instead, so a
// dry-run never shows a password; which attributes those are depends on the server (unicodePwd, userPassword).
type Writer struct {
	W      io.Writer
	Secret []string
}

func (w Writer) secret(name string) bool {
	for _, s := range w.Secret {
		if strings.EqualFold(s, name) {
			return true
		}
	}
	return false
}

func (w Writer) attrs(attrs map[string][]string) {
	names := make([]string, 0, len(attrs))
	for n := range attrs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if w.secret(n) {
			fmt.Fprintf(w.W, "# %s: <redacted>\n", n)
			continue
		}
		for _, v := range attrs[n] {
			fmt.Fprintln(w.W, Line(n, v))
		}
	}
}

// Add writes an add record. controls go on "control:" lines between dn and changetype (RFC 2849), which
// ldapmodify sends with the request.
func (w Writer) Add(dn string, attrs map[string][]string, controls ...directory.Control) {
	fmt.Fprintln(w.W, Line("dn", dn))
	for _, c := range controls {
		fmt.Fprintf(w.W, "control: %s %t\n", c.OID, c.Critical)
	}
	fmt.Fprintln(w.W, "changetype: add")
	w.attrs(attrs)
	fmt.Fprintln(w.W)
}

func (w Writer) Replace(dn string, attrs map[string][]string) {
	fmt.Fprintln(w.W, Line("dn", dn))
	fmt.Fprintln(w.W, "changetype: modify")
	names := make([]string, 0, len(attrs))
	for n := range attrs {
		names = append(names, n)
	}
	sort.Strings(names)
	for i, n := range names {
		if i > 0 {
			fmt.Fprintln(w.W, "-")
		}
		fmt.Fprintf(w.W, "replace: %s\n", n)
		w.attrs(map[string][]string{n: attrs[n]})
	}
	fmt.Fprintln(w.W)
}

// Deferred writes a modify record as comments, with why it is not applied: the record shows what clone would do,
// and ldapmodify skips it.
func (w Writer) Deferred(dn string, attrs map[string][]string, why string) {
	fmt.Fprintf(w.W, "# %s\n", why)
	var b strings.Builder
	Writer{W: &b, Secret: w.Secret}.Replace(dn, attrs)
	for _, l := range strings.Split(strings.TrimRight(b.String(), "\n"), "\n") {
		if strings.HasPrefix(l, "#") {
			fmt.Fprintln(w.W, l)
		} else {
			fmt.Fprintln(w.W, "# "+l)
		}
	}
	fmt.Fprintln(w.W)
}

func (w Writer) DeleteValues(dn, attr string, values []string) {
	fmt.Fprintln(w.W, Line("dn", dn))
	fmt.Fprintln(w.W, "changetype: modify")
	fmt.Fprintf(w.W, "delete: %s\n", attr)
	w.attrs(map[string][]string{attr: values})
	fmt.Fprintln(w.W)
}

func (w Writer) AddValues(dn, attr string, values []string) {
	fmt.Fprintln(w.W, Line("dn", dn))
	fmt.Fprintln(w.W, "changetype: modify")
	fmt.Fprintf(w.W, "add: %s\n", attr)
	w.attrs(map[string][]string{attr: values})
	fmt.Fprintln(w.W)
}

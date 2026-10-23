package app

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// The statuses ListAttrs gives an attribute, in the order it lists them.
const (
	attrNotCopied = "not copied"
	attrCopied    = "copied"
	attrMasked    = "masked"
	attrMarker    = "marker"
	attrNever     = "never"
)

var statusOrder = map[string]int{attrNotCopied: 0, attrCopied: 1, attrMasked: 2, attrMarker: 3, attrNever: 4}

type attrLine struct {
	status, name, note string
	count              int
}

// writeAttrTable lists, per kind, the attributes its entries hold with the number of entries holding each, and what
// clone does with it: copied (or masked), not copied (no allow list names it), or never (credentials and what the
// server manages). Nothing is left out: the attributes of the allow lists no entry holds follow, their names run
// together per status (there are hundreds with mode = "all"), but one with a note gets a line of its own. With the
// target's schema (targetHas, nil when not read) an attribute it lacks is noted, and so is one it refuses. writable
// (per class, nil when the profile cannot tell) makes what no client can write never instead of not copied.
func (s *Session) writeAttrTable(out io.Writer, usage []plan.Usage, writable map[string]map[string]bool, targetHas map[string]bool, refused map[string]string) error {
	_, marker, err := s.Cfg.MappingFor(s.Job.Profile)
	if err != nil {
		return err
	}
	for _, u := range usage {
		allowed := profile.Set(u.Kind.Attrs)
		var lines []attrLine
		noted := func(key string) (string, string) {
			st, note := s.attrStatus(u.Kind.Name, allowed, key, marker)
			if w := writable[u.Kind.Class]; st == attrNotCopied && w != nil && !w[key] {
				st, note = attrNever, "only the server writes it"
			}
			if targetHas != nil && !targetHas[key] && st != attrNever {
				note = strings.TrimPrefix(note+"; not in the target schema", "; ")
			}
			if why, ok := refused[key]; ok && st != attrNever {
				note = strings.TrimPrefix(note+"; left out for this target: "+why, "; ")
			}
			return st, note
		}
		for key, n := range u.Attrs {
			st, note := noted(key)
			lines = append(lines, attrLine{status: st, name: u.Names[key], count: n, note: note})
		}
		unheld := map[string][]string{} // status -> names no entry holds, without a note
		for _, a := range u.Kind.Attrs {
			if _, held := u.Attrs[strings.ToLower(a)]; held {
				continue
			}
			if st, note := noted(strings.ToLower(a)); note != "" {
				lines = append(lines, attrLine{status: st, name: a, note: note})
			} else {
				unheld[st] = append(unheld[st], a)
			}
		}
		sort.Slice(lines, func(i, j int) bool {
			a, b := lines[i], lines[j]
			if statusOrder[a.status] != statusOrder[b.status] {
				return statusOrder[a.status] < statusOrder[b.status]
			}
			if a.count != b.count {
				return a.count > b.count
			}
			return strings.ToLower(a.name) < strings.ToLower(b.name)
		})
		width := 0
		for _, l := range lines {
			width = max(width, len(l.name))
		}
		fmt.Fprintf(out, "[%s] %d entries under %s\n", u.Kind.Name, u.Entries, strings.Join(s.Job.BaseDNs, "; "))
		for _, l := range lines {
			line := fmt.Sprintf("  %-10s  %-*s  %7d", l.status, width, l.name, l.count)
			if l.note != "" {
				line += "  " + l.note
			}
			fmt.Fprintln(out, line)
		}
		for _, st := range []string{attrNotCopied, attrCopied, attrMasked, attrMarker, attrNever} {
			if names := unheld[st]; len(names) > 0 {
				sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
				fmt.Fprintf(out, "  %-10s  no entry holds these %d:\n", st, len(names))
				writeNames(out, names, "                ", 100)
			}
		}
		fmt.Fprintln(out)
	}
	return nil
}

// attrStatus is what clone does with the attribute key (lowercase) of kind, whose allow list is allowed, and why.
func (s *Session) attrStatus(kind string, allowed map[string]bool, key, marker string) (string, string) {
	prof := s.Job.Profile
	switch {
	case profile.Set(prof.PasswordAttrs)[key] && profile.Set(prof.Secrets)[key]:
		return attrNever, `credential; [attributes] credentials = "copy" copies it`
	case profile.Set(prof.PasswordAttrs)[key]:
		return attrNever, "credential"
	case prof.Descriptors != nil && strings.EqualFold(key, prof.Descriptors.Attr()):
		switch s.Job.ACL {
		case plan.ACLTranslated:
			return attrCopied, "the owner, group and explicit ACEs, each SID the target's"
		case plan.ACLAsIs:
			return attrCopied, "as it is, by the native import"
		}
		return attrNotCopied, `ACL; [attributes] acl = "copy" copies it`
	case profile.Set(prof.NeverClone)[key] || strings.EqualFold(key, prof.Identity.Attr()):
		return attrNever, "managed by the server"
	case marker != "" && strings.EqualFold(key, marker):
		return attrMarker, "clone writes the marker here"
	case allowed[key] && s.Job.Masker.MaskedIn(kind, key):
		return attrMasked, ""
	case allowed[key]:
		return attrCopied, ""
	case s.Job.AllWritable && prof.NotAll[key] != "":
		return attrNotCopied, prof.NotAll[key]
	case s.Job.AllWritable:
		return attrNotCopied, "[attributes] exclude names it"
	}
	return attrNotCopied, ""
}

// writeNames writes names separated by commas, in lines of at most width columns that start with indent.
func writeNames(out io.Writer, names []string, indent string, width int) {
	line := indent
	for i, n := range names {
		item := n
		if i < len(names)-1 {
			item += ","
		}
		if line != indent && len(line)+1+len(item) > width {
			fmt.Fprintln(out, line)
			line = indent
		}
		if line != indent {
			line += " "
		}
		line += item
	}
	fmt.Fprintln(out, line)
}

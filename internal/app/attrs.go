package app

import (
	"context"
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

// ListAttrs reads the entries of each kind under base_dn and lists, per kind, the attributes they hold with the
// number of entries holding each, and what clone does with it: copied (or masked), not copied (no allow list names
// it: add it with [attributes] extra_include), or never (credentials and what the server manages). Nothing is left
// out: the attributes of the allow lists no entry holds follow, their names run together per status (there are
// hundreds with mode = "all"), but one with a note gets a line of its own. With withTarget the target's schema is
// read too, and an attribute it lacks is noted. It is as much reading as a clone, and writes nothing.
func (s *Session) ListAttrs(ctx context.Context, withTarget bool, out io.Writer) error {
	usage, err := plan.Survey(ctx, s.Src, s.Job)
	if err != nil {
		return err
	}
	var targetHas map[string]bool
	refused := map[string]string{}
	if withTarget && (s.Job.Profile.SchemaAttrs != nil || s.Job.Profile.Refusals != nil) {
		dst, closeTarget, err := s.Target(ctx)
		if err != nil {
			return err
		}
		defer closeTarget()
		if s.Job.Profile.SchemaAttrs != nil {
			has, ok, err := s.Job.Profile.SchemaAttrs.Attributes(ctx, dst)
			if err != nil {
				return err
			}
			if ok {
				targetHas = has
			}
		}
		if s.Job.Profile.Refusals != nil {
			got, err := s.Job.Profile.Refusals.Refused(ctx, dst)
			if err != nil {
				return err
			}
			for name, why := range got {
				refused[strings.ToLower(name)] = why
			}
		}
	}
	_, marker, err := s.Cfg.MappingFor(s.Job.Profile)
	if err != nil {
		return err
	}
	prof := s.Job.Profile
	creds, never := profile.Set(prof.PasswordAttrs), profile.Set(prof.NeverClone)
	for _, u := range usage {
		allowed := profile.Set(u.Kind.Attrs)
		var lines []attrLine
		status := func(key string) (string, string) {
			switch {
			case creds[key]:
				return attrNever, "credential"
			case never[key] || strings.EqualFold(key, prof.Identity.Attr()):
				return attrNever, "managed by the server"
			case marker != "" && strings.EqualFold(key, marker):
				return attrMarker, "clone writes the marker here"
			case allowed[key] && s.Job.Masker.Masked(key):
				return attrMasked, ""
			case allowed[key]:
				return attrCopied, ""
			}
			return attrNotCopied, ""
		}
		noted := func(key string) (string, string) {
			st, note := status(key)
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
		fmt.Fprintf(out, "[%s] %d entries under %s\n", u.Kind.Name, u.Entries, s.Job.BaseDN)
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
	if s.Job.AllWritable {
		fmt.Fprintln(out, "not copied: [attributes] exclude names it, or the source's schema does not let a client write it on the kind's class")
	} else {
		fmt.Fprintln(out, "not copied: no allow list names it; add it with [attributes] extra_include (or include.<kind>) to copy and compare it")
	}
	if !withTarget {
		fmt.Fprintln(out, "add -target to see which of them the target's schema lacks")
	} else if s.Job.Profile.SchemaCopy != nil {
		fmt.Fprintln(out, "not in the target schema: ldap-cronin schema prints what the target's schema lacks as LDIF (-apply writes it)")
	}
	return nil
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

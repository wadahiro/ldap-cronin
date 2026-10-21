package app

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// Exit codes of check.
const (
	CheckReady   = 0 // clone can run (what it leaves behind is reported, not a failure)
	CheckBlocked = 1 // clone would refuse to start (the target's schema lacks attributes the allow lists name, ...)
)

// CheckOptions are what check reads and shows.
type CheckOptions struct {
	// NoTarget reads the source alone (a machine that reaches production only, or a dump before the lab exists).
	NoTarget bool
	// Attrs adds the table of every attribute of every kind, held or named, and what clone does with it.
	Attrs bool
	// Config is the config file's path, for the commands check prints.
	Config string
}

// Check reads the source (a server or a dump) and the target and says, before anything is written, what clone
// would do: the attributes the entries hold that it would not copy (with the [attributes] line that copies them),
// what the target's schema lacks (with the schema command), what the target refuses, and whether clone can start.
// It ends with the next steps. It writes nothing and asks for no fixed password. It reads as much as a clone does.
func (s *Session) Check(ctx context.Context, o CheckOptions, out io.Writer) (int, error) {
	prof := s.Job.Profile
	cfg := "-config " + o.Config
	phases := len(s.Job.Kinds)
	if !o.NoTarget {
		phases++
	}
	s.Progress.Phases(phases)
	usage, err := plan.Survey(ctx, s.Src, s.Job, s.Progress)
	if err != nil {
		return 0, err
	}
	_, marker, err := s.Cfg.MappingFor(prof)
	if err != nil {
		return 0, err
	}
	// What a client can write on each kind's class, to keep out of the suggestion what only the server writes.
	var writable map[string]map[string]bool
	if prof.Writable != nil {
		var classes []string
		for _, k := range s.Job.Kinds {
			classes = append(classes, k.Class)
		}
		byClass, ok, err := prof.Writable.Writable(ctx, s.Src, classes)
		if err != nil {
			return 0, err
		}
		if ok {
			writable = map[string]map[string]bool{}
			for class, names := range byClass {
				writable[class] = profile.Set(names)
			}
		}
	}

	source := s.Cfg.Source.URL
	if s.Cfg.Source.LDIF != "" {
		source = "the dump " + s.Cfg.Source.LDIF
	}
	fmt.Fprintf(out, "source: %s%s\n", source, serverName(ctx, s.Src))

	var (
		has      map[string]bool
		refused  = map[string]string{}
		left     leftOut
		blocking []string
		changes  profile.SchemaChanges
		warning  string
		refusal  string // why else clone would refuse to start
	)
	if o.NoTarget {
		fmt.Fprintln(out, "target: not read (-no-target)")
	} else {
		s.Progress.Phase("the target's schema", -1)
		dst, closeTarget, err := s.Target(ctx)
		if err != nil {
			return 0, err
		}
		defer closeTarget()
		fmt.Fprintf(out, "target: %s%s\n", s.Cfg.Target.URL, serverName(ctx, dst))
		if has, err = s.targetSchema(ctx, dst); err != nil {
			return 0, err
		}
		if refused, err = s.targetRefusals(ctx, dst); err != nil {
			return 0, err
		}
		job, l, err := s.targetHas(ctx, dst)
		if err != nil {
			return 0, err
		}
		left = l
		if blocking, err = plan.MissingOnTarget(ctx, s.Src, dst, job); err != nil {
			return 0, err
		}
		if prof.SchemaCopy != nil {
			c, ok, err := prof.SchemaCopy.PlanSchema(ctx, s.Src, dst)
			if err != nil {
				return 0, err
			}
			if ok {
				changes = c
			}
		}
		if mode, attr, _ := s.Cfg.MappingFor(prof); mode == config.MappingMarker && prof.MarkerCheck != nil {
			// What stops clone is one more reason it would refuse, not a failure of check.
			if warning, err = prof.MarkerCheck.CheckMarker(ctx, dst, attr, identity.MarkerLen); err != nil {
				refusal = err.Error()
			}
		}
	}
	fmt.Fprintln(out)

	// Per kind: what the entries hold that clone would not copy.
	suggest := map[string]string{} // lowercase -> name
	var lacking []string           // suggested, but the target schema lacks them: schema first
	for _, u := range usage {
		allowed := profile.Set(u.Kind.Attrs)
		type held struct {
			name  string
			count int
		}
		var notCopied []held
		managed := 0
		for key, n := range u.Attrs {
			if st, _ := s.attrStatus(allowed, key, marker); st != attrNotCopied {
				continue
			}
			if w := writable[u.Kind.Class]; writable != nil && !w[key] {
				managed++
				continue
			}
			notCopied = append(notCopied, held{u.Names[key], n})
		}
		sort.Slice(notCopied, func(i, j int) bool {
			if notCopied[i].count != notCopied[j].count {
				return notCopied[i].count > notCopied[j].count
			}
			return strings.ToLower(notCopied[i].name) < strings.ToLower(notCopied[j].name)
		})
		fmt.Fprintf(out, "[%s] %d entries", u.Kind.Name, u.Entries)
		switch {
		case len(notCopied) == 0 && s.Job.AllWritable:
			fmt.Fprintln(out, ": clone copies every attribute they hold that a client can write (mode = \"all\")")
		case len(notCopied) == 0:
			fmt.Fprintln(out, ": clone copies every attribute they hold that a client can write")
		case s.Job.AllWritable:
			fmt.Fprintf(out, "; %d attributes they hold are not copied ([attributes] exclude names them):\n", len(notCopied))
		default:
			fmt.Fprintf(out, "; %d attributes they hold are not copied (no allow list names them):\n", len(notCopied))
		}
		width := 0
		for _, h := range notCopied {
			width = max(width, len(h.name))
		}
		for _, h := range notCopied {
			line := fmt.Sprintf("  %-*s  %7d", width, h.name, h.count)
			key := strings.ToLower(h.name)
			if has != nil && !has[key] {
				line += "  the target schema lacks it"
			}
			if why, ok := refused[key]; ok {
				line += "  the target refuses it: " + why
			}
			fmt.Fprintln(out, line)
			if s.Job.AllWritable {
				continue
			}
			if _, ok := refused[key]; ok {
				continue
			}
			suggest[key] = h.name
			if has != nil && !has[key] {
				lacking = append(lacking, h.name)
			}
		}
		if managed > 0 {
			fmt.Fprintf(out, "  (and %d more only the server writes; -attrs lists every attribute)\n", managed)
		}
	}
	fmt.Fprintln(out)

	if len(blocking) > 0 {
		fmt.Fprintf(out, "clone refuses to start: the target schema lacks %d attributes the allow lists name:\n", len(blocking))
		for _, b := range blocking {
			fmt.Fprintf(out, "  %s\n", b)
		}
	}
	if refusal != "" {
		fmt.Fprintf(out, "clone refuses to start: %s\n", refusal)
	}
	noteLeftOut(out, left)
	if warning != "" {
		fmt.Fprintf(out, "warning: %s\n", warning)
	}
	if changes != nil && !changes.Empty() {
		fmt.Fprintln(out, "the target schema lacks definitions of the source's (ldap-cronin schema adds them):")
		var b strings.Builder
		changes.WriteSummary(&b)
		for _, l := range strings.Split(strings.TrimRight(b.String(), "\n"), "\n") {
			fmt.Fprintf(out, "  %s\n", l)
		}
	}
	// One empty line between the parts: after the notes when there were any.
	if notes := len(blocking) > 0 || refusal != "" || len(left.missing)+len(left.refused) > 0 || warning != "" || (changes != nil && !changes.Empty()); notes {
		fmt.Fprintln(out)
	}
	if o.Attrs {
		if err := s.writeAttrTable(out, usage, has, refused); err != nil {
			return 0, err
		}
	}

	// The next steps, in order, with what to paste and what to run.
	fmt.Fprintln(out, "next:")
	step := 0
	next := func(format string, a ...any) {
		step++
		fmt.Fprintf(out, "  %d. "+format+"\n", append([]any{step}, a...)...)
	}
	needSchema := len(blocking) > 0 || len(lacking) > 0 || (changes != nil && !changes.Empty())
	if len(suggest) > 0 {
		names := append([]string(nil), s.Cfg.Attributes.Extra...)
		seen := profile.Set(names)
		for key, n := range suggest {
			if !seen[key] {
				names = append(names, n)
			}
		}
		sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
		quoted := make([]string, len(names))
		for i, n := range names {
			quoted[i] = strconv.Quote(n)
		}
		next("to copy and compare what clone leaves behind, put in %s (keep only those you want):", o.Config)
		fmt.Fprintf(out, "       [attributes]\n       extra_include = [%s]\n", strings.Join(quoted, ", "))
		if prof.Writable != nil {
			fmt.Fprintln(out, "     or copy every attribute a client can write: [attributes] mode = \"all\"")
		}
	}
	if needSchema {
		if prof.SchemaCopy != nil {
			next("give the target the source's definitions: ldap-cronin schema %s -apply", cfg)
			fmt.Fprintf(out, "     (a test AD: ldap-cronin schema %s > schema.ldif, for a Schema Admin; it cannot be undone)\n", cfg)
		} else {
			next("give the target's schema the attributes it lacks (above)")
		}
	}
	if len(suggest) > 0 || needSchema || o.NoTarget {
		next("check again: ldap-cronin check %s", cfg)
	}
	if o.NoTarget {
		fmt.Fprintln(out, "     (with the target, so it can say what the target's schema lacks)")
	}
	next("clone: ldap-cronin clone %s", cfg)
	if len(blocking) > 0 || refusal != "" {
		return CheckBlocked, nil
	}
	return CheckReady, nil
}

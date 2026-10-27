package app

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/lab"
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
	// Lab is the lab [target.lab] names (nil without it): check says whether clone creates or starts it.
	Lab *lab.Lab
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
		target   directory.Directory
	)
	// A lab: whether lab up --config has made it (and started it), so it can be read and written.
	var labNote string
	inLab := s.Cfg.Target.Lab != nil && o.Lab != nil
	if inLab && !o.NoTarget {
		state, err := s.labState(ctx, o.Lab)
		if err != nil {
			return 0, err
		}
		if labNote = labNotReady(state, o.Lab, o.Config); labNote == "" {
			if err := o.Lab.CheckTargetURL(ctx, s.Cfg.Target.URL); err != nil {
				refusal = err.Error()
			}
		}
	}
	native := s.Cfg.NativeLab() != nil
	switch {
	case o.NoTarget:
		fmt.Fprintln(out, "target: not read (-no-target)")
	case labNote != "":
		fmt.Fprintf(out, "target: %s\n", labNote)
	default:
		s.Progress.Phase("the target's schema", -1)
		dst, closeTarget, err := s.Target(ctx)
		if err != nil {
			return 0, err
		}
		defer closeTarget()
		target = dst
		switch {
		case inLab && native:
			fmt.Fprintf(out, "target: the lab %s (%s%s), its database written directly\n", o.Lab.Name(), s.Cfg.Target.URL, serverName(ctx, dst))
		case inLab:
			fmt.Fprintf(out, "target: the lab %s (%s%s)\n", o.Lab.Name(), s.Cfg.Target.URL, serverName(ctx, dst))
		default:
			fmt.Fprintf(out, "target: %s%s\n", s.Cfg.Target.URL, serverName(ctx, dst))
		}
		if native && refusal == "" {
			if refusal, err = s.sameDomain(ctx, dst); err != nil {
				return 0, err
			}
		}
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
			why   string
		}
		var notCopied, noted []held
		managed := 0
		for key, n := range u.Attrs {
			st, why := s.attrStatus(u.Kind.Name, allowed, key, marker)
			if st == attrCopied && prof.CopyNotes[key] != "" {
				noted = append(noted, held{u.Names[key], n, prof.CopyNotes[key]})
			}
			if st != attrNotCopied {
				continue
			}
			if w := writable[u.Kind.Class]; writable != nil && !w[key] {
				managed++
				continue
			}
			notCopied = append(notCopied, held{u.Names[key], n, why})
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
			fmt.Fprintf(out, "; %d attributes they hold are not copied:\n", len(notCopied))
		default:
			fmt.Fprintf(out, "; %d attributes they hold are not copied (no allow list names them):\n", len(notCopied))
		}
		width := 0
		for _, h := range notCopied {
			width = max(width, len(h.name))
		}
		for _, h := range notCopied {
			line := fmt.Sprintf("  %-*s  %7d", width, h.name, h.count)
			if h.why != "" {
				line += "  " + h.why
			}
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
		sort.Slice(noted, func(i, j int) bool { return strings.ToLower(noted[i].name) < strings.ToLower(noted[j].name) })
		for _, h := range noted {
			fmt.Fprintf(out, "  note: %s (%d entries): %s\n", h.name, h.count, h.why)
		}
	}
	if err := s.writeHolders(ctx, out); err != nil {
		return 0, err
	}
	fmt.Fprintln(out)

	// The values the target holds once (without one read, the strictest rules: Samba's).
	root, err := plan.Root(ctx, s.Src, s.Job)
	if err != nil {
		return 0, err
	}
	withheld, clashes, err := plan.Withholding(ctx, s.Src, target, s.Job, root)
	if err != nil {
		return 0, err
	}
	writeWithheld(out, withheld)

	if len(blocking) > 0 {
		fmt.Fprintf(out, "clone refuses to start: the target schema lacks %d attributes the allow lists name:\n", len(blocking))
		for _, b := range blocking {
			fmt.Fprintf(out, "  %s\n", b)
		}
	}
	if refusal != "" {
		fmt.Fprintf(out, "clone refuses to start: %s\n", refusal)
	}
	if len(clashes) > 0 {
		fmt.Fprintf(out, "clone refuses to start: %v\n", plan.ClashError(clashes))
	}
	noteLeftOut(out, left)
	if warning != "" {
		fmt.Fprintf(out, "warning: %s\n", warning)
	}
	if changes != nil && !changes.Empty() {
		if inLab {
			fmt.Fprintln(out, "the lab's schema lacks definitions of the source's (lab up --config adds them):")
		} else {
			fmt.Fprintln(out, "the target schema lacks definitions of the source's (ldap-cronin schema adds them):")
		}
		var b strings.Builder
		changes.WriteSummary(&b)
		for _, l := range strings.Split(strings.TrimRight(b.String(), "\n"), "\n") {
			fmt.Fprintf(out, "  %s\n", l)
		}
	}
	// One empty line between the parts: after the notes when there were any.
	if notes := len(blocking) > 0 || refusal != "" || len(clashes) > 0 || len(left.missing)+len(left.refused) > 0 || warning != "" || (changes != nil && !changes.Empty()); notes {
		fmt.Fprintln(out)
	}
	if o.Attrs {
		if err := s.writeAttrTable(out, usage, writable, has, refused); err != nil {
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
	if labNote != "" {
		next("make the lab: ldap-cronin lab up --config %s", o.Config)
	}
	if needSchema {
		if inLab {
			next("give the lab's schema the source's definitions: ldap-cronin lab up --config %s", o.Config)
		} else if prof.SchemaCopy != nil {
			next("give the target the source's definitions: ldap-cronin schema %s -apply", cfg)
			fmt.Fprintf(out, "     (a test AD: ldap-cronin schema %s > schema.ldif, for a Schema Admin; it cannot be undone)\n", cfg)
		} else {
			next("give the target's schema the attributes it lacks (above)")
		}
	}
	if len(suggest) > 0 || needSchema || o.NoTarget || labNote != "" {
		next("check again: ldap-cronin check %s", cfg)
	}
	if o.NoTarget {
		fmt.Fprintln(out, "     (with the target, so it can say what the target's schema lacks)")
	}
	next("clone: ldap-cronin clone %s", cfg)
	if len(blocking) > 0 || refusal != "" || labNote != "" || len(clashes) > 0 {
		return CheckBlocked, nil
	}
	return CheckReady, nil
}

// sameDomain says why a native import into dst would refuse: the lab's domain (root, SID, GUID) is not the
// source's. It reads the lab over LDAP, as check writes nothing and does not stop it.
func (s *Session) sameDomain(ctx context.Context, dst directory.Directory) (string, error) {
	src, err := s.domain(ctx)
	if err != nil {
		return err.Error(), nil
	}
	d, err := s.Job.Profile.Native.Domain(ctx, dst, src.Root)
	if err != nil {
		return "", fmt.Errorf("target: %w", err)
	}
	if err := checkSameDomain(lab.NativeInfo{Base: d.Root, DomainSID: d.SID, DomainGUID: d.GUID}, src); err != nil {
		return err.Error(), nil
	}
	return "", nil
}

// writeHolders says which groups outside base_dn hold entries of it (their memberOf), and what clone does with
// each: the memberships are the groups' values, which the entries alone do not carry.
func (s *Session) writeHolders(ctx context.Context, out io.Writer) error {
	p, err := plan.Build(ctx, s.Src, s.Job, plan.Read{})
	if err != nil {
		return err
	}
	hs, err := p.Holders(ctx)
	if err != nil || len(hs) == 0 {
		return err
	}
	given := map[string]int{}
	left := map[string]int{}
	for _, h := range hs {
		switch {
		case h.Why != "":
			left[h.Why]++
		case h.Builtin:
			given["built-in (the target's own get the members)"]++
		case h.Existing:
			given["outside base_dn, if the target holds them ([scope] outside_groups = \"existing\")"]++
		default:
			given["outside base_dn (clone creates them)"]++
		}
	}
	fmt.Fprintln(out)
	if len(given) > 0 {
		plan.WriteCounts(out, "groups holding entries of base_dn that clone gives those members", given)
	}
	if len(left) > 0 {
		plan.WriteCounts(out, "groups holding entries of base_dn that clone leaves as they are", left)
	}
	return nil
}

// maxWithheldShown caps the values check lists; the count is always given.
const maxWithheldShown = 20

// writeWithheld lists the values clone will not write (plan.Withheld), each with the objects that keep it.
func writeWithheld(out io.Writer, w *plan.Withheld) {
	if len(w.Refused) > 0 {
		fmt.Fprintf(out, "entries clone will not add, the target refuses them: %d\n", len(w.Refused))
		for i, e := range w.Refused {
			if i == maxWithheldShown {
				fmt.Fprintf(out, "  ... and %d more (clone warns of each)\n", len(w.Refused)-i)
				break
			}
			fmt.Fprintf(out, "  %s  (%s)\n", e.DN, e.Why)
		}
		fmt.Fprintln(out)
	}
	if len(w.Values) == 0 {
		return
	}
	fmt.Fprintf(out, "values clone will not write, the target refuses them: %d\n", len(w.Values))
	for i, v := range w.Values {
		if i == maxWithheldShown {
			fmt.Fprintf(out, "  ... and %d more (clone warns of each)\n", len(w.Values)-i)
			break
		}
		fmt.Fprintf(out, "  %s %s of %s (kept by %s): %s\n", v.Attr, v.Value, v.DN, strings.Join(v.Others, "; "), v.Why)
	}
	fmt.Fprintln(out)
}

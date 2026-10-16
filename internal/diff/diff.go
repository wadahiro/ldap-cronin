// Package diff compares the clone source and the target with the same scope and attributes as clone.
// Differences are reported as soon as they are found instead of being accumulated, so memory does not grow even when the target is empty and every entry differs.
package diff

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/wadahiro/ldap-cronin/internal/attrs"
	"github.com/wadahiro/ldap-cronin/internal/compare"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/guidmap"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/workpool"
)

type Kind string

const (
	OnlySource Kind = "ONLY_SOURCE" // only on the source, not on the target (not cloned yet)
	OnlyTarget Kind = "ONLY_TARGET" // only on the target, not on the source
	Differ     Kind = "DIFF"        // on both sides, but attribute values differ
	// Renamed means the mapping (GUID) shows that the object at the source DN lives at a different DN on the target.
	// It appears when another program renamed or moved it on the target.
	Renamed Kind = "RENAMED"
	// Replaced means the source DN holds a different object from the one that was cloned (recorded in the mapping),
	// and the original object exists nowhere. It appears when the object was deleted and recreated at the same DN.
	Replaced Kind = "REPLACED"
)

type Difference struct {
	Kind   Kind
	DN     string
	Attr   string
	Source []string
	Target []string
	// For multi-valued attributes, which side alone holds each value (listing all values would make member and the like unreadable).
	OnlySource []string
	OnlyTarget []string
	Multi      bool
	// CaseOnly means the difference is only in letter case. For a single value, the two values are equal ignoring case;
	// for multi-valued attributes, every differing value has a counterpart on the other side that differs only in case. It still counts as a difference.
	CaseOnly bool
	// For multi-valued attributes, whether each OnlySource / OnlyTarget value has a counterpart on the other side that differs only in case.
	SourceCasePair []bool
	TargetCasePair []bool

	// For Renamed, the current DN on the target and whether it is a rename (RDN change) or a move (parent change).
	TargetDN   string
	RDNRenamed bool
	Moved      bool
}

// Summary is the compared scope and the number of differences.
type Summary struct {
	Compared    map[string]int // number of objects compared per kind
	Differences map[Kind]int
	CaseOnly    int // number of DIFF entries that differ only in case

	Tracking     bool // whether renames and moves were detected using the mapping
	Identity     bool // whether entries were matched on the assumption that objectGUID is identical, instead of using the mapping
	TrackedPairs int  // number of entries in the mapping
	Implied      int  // number not reported as RENAMED because a parent OU move or rename explains them
}

// Run reports each difference to emit one at a time. emit is not called from multiple goroutines.
// Masked attributes are not compared, since their values are expected to differ.
// For DN reference attributes, out-of-plan values (built-ins, etc.) are excluded from both sides before comparing.
//
// If guids (the GUID mapping between source and target) is given, objects whose source DN is missing on the target are looked up by GUID,
// and reported as RENAMED if found at a different DN. This verifies changes made by another program that renamed or moved objects on the target.
func Run(src, dst directory.Directory, opt plan.Options, workers int, guids *guidmap.Map, emit func(Difference)) (Summary, error) {
	if guids == nil {
		return RunWith(src, dst, opt, workers, nil, emit)
	}
	return RunWith(src, dst, opt, workers, guids, emit)
}

// RunWith is Run taking the mapping as an interface. Passing guidmap.Identity detects renames and moves without a mapping,
// on the assumption that the target objectGUID equals the source (native import). With nil, nothing is detected.
func RunWith(src, dst directory.Directory, opt plan.Options, workers int, guids guidmap.Lookup, emit func(Difference)) (Summary, error) {
	sum := Summary{Compared: map[string]int{}, Differences: map[Kind]int{}}
	if guids != nil {
		opt.TrackGUID = true
		_, sum.Identity = guids.(guidmap.Identity)
		sum.Tracking, sum.TrackedPairs = true, guids.Len()
	}
	p, err := plan.Build(src, opt)
	if err != nil {
		return sum, err
	}
	var mu sync.Mutex
	report := func(d Difference) {
		mu.Lock()
		defer mu.Unlock()
		sum.Differences[d.Kind]++
		if d.Kind == Differ && d.CaseOnly {
			sum.CaseOnly++
		}
		emit(d)
	}
	compared := func(kind string) {
		mu.Lock()
		defer mu.Unlock()
		sum.Compared[kind]++
	}
	loc := &locator{idAttr: opt.IDAttr(), idText: opt.P().IDIsText, dst: dst, domain: p.Domain, guids: guids, targetOf: map[string]string{}, found: plan.NewScope(), renamedBack: map[string]string{}}
	var (
		pendMu  sync.Mutex
		pending []pendingRef
	)
	deferRef := func(dnStr, name string, want, got []string) {
		pendMu.Lock()
		defer pendMu.Unlock()
		pending = append(pending, pendingRef{dn: dnStr, name: name, want: want, got: got})
	}

	// Parents and OUs are processed by depth, shallowest first. To know the "expected parent DN" of a child,
	// where its parent lives on the target (whether it moved) must already be known.
	type structural struct {
		entry   directory.Entry
		compare bool
	}
	var items []structural
	for _, a := range p.Ancestors {
		items = append(items, structural{a, false})
	}
	if opt.Enabled(attrs.KindOU) {
		for _, o := range p.OUs {
			items = append(items, structural{o, true})
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return dn.Depth(items[i].entry.DN) < dn.Depth(items[j].entry.DN) })
	for len(items) > 0 {
		depth := dn.Depth(items[0].entry.DN)
		n := 0
		for n < len(items) && dn.Depth(items[n].entry.DN) == depth {
			n++
		}
		err := workpool.Each(workers, items[:n], func(it structural) error {
			names := []string{"objectClass"}
			kind := ""
			if it.compare {
				names, kind = opt.Attrs[attrs.KindOU], attrs.KindOU
				compared(kind)
			}
			return check(loc, it.entry, names, opt, p, kind, true, report, deferRef, &mu, &sum)
		})
		if err != nil {
			return sum, err
		}
		items = items[n:]
	}

	for _, kind := range []string{attrs.KindGroup, attrs.KindUser} {
		if !opt.Enabled(kind) {
			continue
		}
		err := workpool.Feed(workers, func(emit func(directory.Entry) error) error {
			return p.Walk(kind, opt.Attrs[kind], emit)
		}, func(want directory.Entry) error {
			compared(kind)
			return check(loc, want, opt.Attrs[kind], opt, p, kind, false, report, deferRef, &mu, &sum)
		})
		if err != nil {
			return sum, err
		}
	}

	resolveRefs(pending, loc, p, report)

	for _, kind := range attrs.SortedKinds(opt.Kinds) {
		err := dst.Walk(opt.BaseDN, opt.SearchFilter(kind), []string{directory.NoAttrs}, func(e directory.Entry) error {
			// Entries matched by GUID are RENAMED (or already explained by a parent move), so they are not target-only.
			if !p.Scope.Has(e.DN) && !loc.found.Has(e.DN) {
				report(Difference{Kind: OnlyTarget, DN: e.DN})
			}
			return nil
		})
		if err != nil {
			return sum, fmt.Errorf("scan target %s: %w", kind, err)
		}
	}
	return sum, nil
}

// check matches one source entry against the target and reports the differences.
// A parent container with compareAttrs false is checked only for existence, rename and move.
func check(loc *locator, want directory.Entry, names []string, opt plan.Options, p *plan.Plan, kind string,
	structural bool, report func(Difference), deferRef deferRefFunc, mu *sync.Mutex, sum *Summary) error {
	res, err := loc.locate(want, names)
	if err != nil {
		return err
	}
	if res.replacedBy != "" {
		if res.entry == nil { // the original object is gone and a different object sits at the same DN
			report(Difference{Kind: Replaced, DN: want.DN})
			// Even for a different object we want to know how it differs from the source values, so compare the attributes.
			if kind != "" {
				compareEntry(want, *res.replacement, names, opt, p, "", deferRef, report)
			}
			return nil
		}
		// The original object moved elsewhere and a different object was created at the original DN. The latter is not on the source.
		report(Difference{Kind: OnlyTarget, DN: res.replacedBy})
	}
	got, viaGUID := res.entry, res.viaGUID
	if got == nil {
		report(Difference{Kind: OnlySource, DN: want.DN})
		return nil
	}
	shown := want
	skip := "" // attribute not compared because a rename explains it (the RDN attribute)
	if viaGUID {
		loc.noteRenamed(want.DN, got.DN)
		renamed, moved := loc.classify(want.DN, got.DN)
		if renamed {
			// Changing the RDN makes the server change cn (ou for an OU) as well. It is a result of the rename, so it is not reported as a separate difference.
			// If the target value disagrees with the new RDN, however, that is a real difference and is reported.
			if typ, val, ok := dn.FirstRDN(got.DN); ok && strings.EqualFold(first(got.Values(typ)), val) {
				skip = typ
			}
		}
		if renamed || moved {
			report(Difference{Kind: Renamed, DN: want.DN, TargetDN: got.DN, RDNRenamed: renamed, Moved: moved})
		} else {
			mu.Lock()
			sum.Implied++
			mu.Unlock()
		}
		shown.DN = got.DN // attribute differences are shown at the current location on the target
	}
	if structural {
		loc.noteTarget(want.DN, got.DN)
	}
	if kind != "" {
		compareEntry(shown, *got, names, opt, p, skip, deferRef, report)
	}
	return nil
}

// locator finds the target entry that corresponds to one source entry.
type locator struct {
	dst    directory.Directory
	domain string
	guids  guidmap.Lookup
	// idAttr is the attribute that identifies an object across renames (objectGUID, entryUUID).
	idAttr string
	idText bool // the identifier is searched as text (entryUUID), not as escaped bytes

	mu       sync.Mutex
	targetOf map[string]string // normalized source DN -> current DN on the target; only for those whose parent moved or was renamed
	found    *plan.Scope       // target DNs found by GUID
	// renamedBack maps the target DN found by GUID (normalized) to the source DN. It is used to translate references pointing at a renamed or moved object
	// back to the original DN.
	renamedBack map[string]string
}

// noteRenamed records that a target object lives at a DN different from its source DN.
func (l *locator) noteRenamed(sourceDN, targetDN string) {
	if dn.Equal(sourceDN, targetDN) {
		return
	}
	l.mu.Lock()
	l.renamedBack[dn.Normalize(targetDN)] = sourceDN
	l.mu.Unlock()
}

// translateBack translates, among the values of a target reference, the DNs of renamed or moved objects back to the source DNs.
func (l *locator) translateBack(values []string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = v
		if src, ok := l.renamedBack[dn.Normalize(v)]; ok {
			out[i] = src
		}
	}
	return out
}

// located is the result of locate.
type located struct {
	entry   *directory.Entry
	viaGUID bool // found by GUID (it was at a place other than the source DN)
	// replacedBy is the DN of a different object that sits at the source DN.
	// It is set when the GUID in the mapping differs from the GUID of the object at that DN.
	replacedBy string
	// replacement is that different object at the DN (the one compared with the source attributes when REPLACED).
	replacement *directory.Entry
}

// locate finds the target entry that corresponds to one source entry.
// It first looks at the same DN and, if there is a mapping, checks by GUID that the entry there is the cloned object.
// If it is a different object, it looks for the original by GUID (if found, it moved elsewhere).
func (l *locator) locate(want directory.Entry, names []string) (located, error) {
	lookup := names
	if l.guids != nil {
		lookup = append(append([]string(nil), names...), l.idAttr)
	}
	got, err := l.dst.Get(want.DN, lookup)
	if err != nil {
		return located{}, err
	}
	if l.guids == nil {
		return located{entry: got}, nil
	}
	target, mapped := l.guids.Target(guidmap.Hex(first(want.Values(l.idAttr))))
	if got != nil {
		gotGUID := guidmap.Hex(first(got.Values(l.idAttr)))
		if !mapped || gotGUID == "" || gotGUID == target {
			return located{entry: got}, nil
		}
		res := located{replacedBy: got.DN, replacement: got}
		orig, err := l.findByGUID(target, names)
		if err != nil {
			return located{}, err
		}
		res.entry, res.viaGUID = orig, orig != nil
		return res, nil
	}
	if !mapped {
		return located{}, nil
	}
	orig, err := l.findByGUID(target, names)
	if err != nil {
		return located{}, err
	}
	return located{entry: orig, viaGUID: orig != nil}, nil
}

// findByGUID looks for an object by GUID across the whole target domain,
// because a move may have taken it outside the starting point. objectGUID is indexed, so this is fast. The DN found is recorded.
func (l *locator) findByGUID(target string, names []string) (*directory.Entry, error) {
	var got *directory.Entry
	value := guidmap.FilterValue(target)
	if l.idText {
		value = guidmap.UUIDText(target)
	}
	filter := "(" + l.idAttr + "=" + value + ")"
	err := l.dst.Walk(l.domain, filter, names, func(e directory.Entry) error {
		if got == nil {
			c := e
			got = &c
		}
		return nil
	})
	if err != nil || got == nil {
		return nil, err
	}
	l.mu.Lock()
	l.found.Add(got.DN)
	l.mu.Unlock()
	return got, nil
}

// classify returns whether the difference between the source DN and the target DN is an RDN change (rename) or a parent change (move).
// If a parent OU moved, the expected parent is the parent's current DN on the target, and a child fully explained by
// its parent move gets false for both (so a large number of children are not reported as RENAMED).
func (l *locator) classify(sourceDN, targetDN string) (renamed, moved bool) {
	expectedParent := dn.Parent(sourceDN)
	l.mu.Lock()
	if t, ok := l.targetOf[dn.Normalize(expectedParent)]; ok {
		expectedParent = t
	}
	l.mu.Unlock()
	renamed = dn.Normalize(dn.Split(sourceDN)[0]) != dn.Normalize(dn.Split(targetDN)[0])
	moved = !dn.Equal(dn.Parent(targetDN), expectedParent)
	return renamed, moved
}

func (l *locator) noteTarget(sourceDN, targetDN string) {
	if dn.Equal(sourceDN, targetDN) {
		return
	}
	l.mu.Lock()
	l.targetOf[dn.Normalize(sourceDN)] = targetDN
	l.mu.Unlock()
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// deferRefFunc defers the comparison of DN reference attributes until after all objects have been matched.
type deferRefFunc func(dn, name string, want, got []string)

func compareEntry(want, got directory.Entry, names []string, opt plan.Options, p *plan.Plan, skip string, deferRef deferRefFunc, report func(Difference)) {
	for _, name := range names {
		if opt.Masker.Masked(name) || (skip != "" && strings.EqualFold(name, skip)) {
			continue
		}
		w, g := want.Values(name), got.Values(name)
		if p.IsRef(name) {
			// The server rewrites a reference pointing at an object renamed on the target to the new DN.
			// Which objects were renamed is unknown until everything has been matched,
			// so only the values that differ as they are get set aside, and are translated and compared later (resolveRefs).
			if !compare.EqualDN(w, g) {
				deferRef(want.DN, name, append([]string(nil), w...), append([]string(nil), g...))
			}
			continue
		}
		if p.Equal(name, w, g) {
			continue
		}
		report(makeDifference(want.DN, name, w, g, false))
	}
}

// makeDifference turns one attribute difference into its display form.
func makeDifference(dn, name string, w, g []string, isRef bool) Difference {
	d := Difference{Kind: Differ, DN: dn, Attr: name, Source: w, Target: g}
	if len(w) > 1 || len(g) > 1 {
		d.Multi = true
		d.OnlySource, d.OnlyTarget = compare.SetDiff(name, isRef, w, g)
		d.Source, d.Target = nil, nil // do not keep or print all values
		if !isRef {                   // DN reference attributes are already normalized as DNs, so case-only differences cannot occur
			d.SourceCasePair, d.TargetCasePair, d.CaseOnly = casePairs(d.OnlySource, d.OnlyTarget)
		}
	} else if len(w) == 1 && len(g) == 1 && strings.EqualFold(w[0], g[0]) {
		d.CaseOnly = true
	}
	return d
}

// pendingRef is a DN reference attribute whose comparison was deferred.
type pendingRef struct {
	dn, name  string
	want, got []string
}

// resolveRefs compares the deferred DN reference attributes. Among the target values, the new DNs of renamed or moved objects
// are translated back to the original (source) DNs, then filtered by the plan scope and compared.
func resolveRefs(pending []pendingRef, loc *locator, p *plan.Plan, report func(Difference)) {
	for _, pr := range pending {
		got := loc.translateBack(pr.got)
		w, g := inScope(pr.want, p.Scope), inScope(got, p.Scope)
		if p.Equal(pr.name, w, g) {
			continue
		}
		report(makeDifference(pr.dn, pr.name, w, g, true))
	}
}

func inScope(values []string, scope *plan.Scope) []string {
	var out []string
	for _, v := range values {
		if scope.Has(v) {
			out = append(out, v)
		}
	}
	return out
}

// DefaultMaxValues is the default cap on values shown per attribute and direction for a multi-valued difference.
const DefaultMaxValues = 10

// Format prints one difference. Multi-valued attributes list one value per line.
// maxValues is the display cap per direction; 0 or less shows everything.
func Format(w io.Writer, d Difference, maxValues int) {
	if d.Kind == Renamed {
		fmt.Fprintf(w, "%-11s source: %s\n", d.Kind, d.DN)
		fmt.Fprintf(w, "            target: %s   (%s)\n", d.TargetDN, renameKind(d))
		return
	}
	fmt.Fprintf(w, "%-11s %s\n", d.Kind, d.DN)
	if d.Kind == Replaced {
		fmt.Fprintln(w, "            same DN, but a different object than the one that was cloned (the original is gone)")
		return
	}
	if d.Kind != Differ {
		return
	}
	if d.CaseOnly && !d.Multi {
		fmt.Fprintf(w, "            %s:  (case only)\n", d.Attr)
	} else {
		fmt.Fprintf(w, "            %s:\n", d.Attr)
	}
	if !d.Multi {
		// Align the start of the values so that it is easy to see where they differ.
		src, tgt := single(d.Source), single(d.Target)
		fmt.Fprintf(w, "              source: %s\n", src)
		var markSrc, markTgt string
		switch {
		case d.CaseOnly:
			markSrc, markTgt = caseMarkers(src, tgt)
		case len(d.Source) > 0 && len(d.Target) > 0:
			markSrc, markTgt = markers(src, tgt)
		}
		if markSrc != "" {
			fmt.Fprintf(w, "%s%s\n", valueIndent, markSrc)
		}
		fmt.Fprintf(w, "              target: %s\n", tgt)
		if markTgt != "" {
			fmt.Fprintf(w, "%s%s\n", valueIndent, markTgt)
		}
		return
	}
	list(w, "only in source", d.OnlySource, d.SourceCasePair, "target", maxValues)
	list(w, "only in target", d.OnlyTarget, d.TargetCasePair, "source", maxValues)
}

func renameKind(d Difference) string {
	switch {
	case d.RDNRenamed && d.Moved:
		return "renamed and moved"
	case d.Moved:
		return "moved"
	default:
		return "renamed"
	}
}

func list(w io.Writer, title string, values []string, casePair []bool, otherSide string, maxValues int) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(w, "              %s (%d):\n", title, len(values))
	shown := values
	if maxValues > 0 && len(values) > maxValues {
		shown = values[:maxValues]
	}
	for i, v := range shown {
		tag := ""
		if i < len(casePair) && casePair[i] {
			tag = fmt.Sprintf("    (case only: same value on %s side)", otherSide)
		}
		fmt.Fprintf(w, "                - %s%s\n", v, tag)
	}
	if len(shown) < len(values) {
		fmt.Fprintf(w, "                ... (+%d more; use -max-values to show more)\n", len(values)-len(shown))
	}
}

// casePairs returns whether each differing value has a counterpart on the other side that differs only in case.
// all is true when every differing value has a counterpart and the counts match (that is, a case-only difference).
func casePairs(onlySource, onlyTarget []string) (srcPair, tgtPair []bool, all bool) {
	folded := func(values []string) map[string]bool {
		m := make(map[string]bool, len(values))
		for _, v := range values {
			m[strings.ToLower(v)] = true
		}
		return m
	}
	inSource, inTarget := folded(onlySource), folded(onlyTarget)
	all = len(onlySource) == len(onlyTarget)
	srcPair = make([]bool, len(onlySource))
	for i, v := range onlySource {
		srcPair[i] = inTarget[strings.ToLower(v)]
		all = all && srcPair[i]
	}
	tgtPair = make([]bool, len(onlyTarget))
	for i, v := range onlyTarget {
		tgtPair[i] = inSource[strings.ToLower(v)]
		all = all && tgtPair[i]
	}
	return srcPair, tgtPair, all
}

// caseMarkers marks case differences with tildes under only the characters that differ.
// Differences are scattered, so this shows what differs better than markers, which draws one line from the first to the last difference.
// If the lengths do not match (case does not map one-to-one), it defers to markers.
func caseMarkers(a, b string) (string, string) {
	ra, rb := []rune(a), []rune(b)
	if len(ra) != len(rb) {
		return markers(a, b)
	}
	var ma, mb strings.Builder
	for i := range ra {
		width := displayWidth(ra[i : i+1])
		mark := " "
		if ra[i] != rb[i] {
			mark = "~"
		}
		ma.WriteString(strings.Repeat(mark, width))
		mb.WriteString(strings.Repeat(mark, displayWidth(rb[i:i+1])))
	}
	return strings.TrimRight(ma.String(), " "), strings.TrimRight(mb.String(), " ")
}

// valueIndent is the width of "              source: ". The marker start is aligned to where the value starts.
const valueIndent = "                      "

// markers returns a line that underlines with tildes the differing span of two values, excluding the common prefix and suffix.
// Like the failure output of a unit test, it shows character by character where they differ.
// If one side has extra characters (its differing span is empty), the position of the extra characters is marked with ^.
func markers(a, b string) (string, string) {
	ra, rb := []rune(a), []rune(b)
	prefix := 0
	for prefix < len(ra) && prefix < len(rb) && ra[prefix] == rb[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(ra)-prefix && suffix < len(rb)-prefix && ra[len(ra)-1-suffix] == rb[len(rb)-1-suffix] {
		suffix++
	}
	return underline(ra, prefix, len(ra)-suffix), underline(rb, prefix, len(rb)-suffix)
}

func underline(r []rune, from, to int) string {
	pad, span := displayWidth(r[:from]), displayWidth(r[from:to])
	if span == 0 {
		return strings.Repeat(" ", pad) + "^"
	}
	return strings.Repeat(" ", pad) + strings.Repeat("~", span)
}

// displayWidth is the display width in a terminal. Full-width characters (Japanese, etc.) count as 2 columns.
func displayWidth(rs []rune) int {
	n := 0
	for _, r := range rs {
		if isWide(r) {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func isWide(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115F, // Hangul Jamo
		r >= 0x2E80 && r <= 0xA4CF, // CJK radicals, Hiragana, Katakana, Han, symbols
		r >= 0xAC00 && r <= 0xD7A3, // Hangul syllables
		r >= 0xF900 && r <= 0xFAFF, // CJK compatibility ideographs
		r >= 0xFE30 && r <= 0xFE6F, // CJK compatibility forms
		r >= 0xFF00 && r <= 0xFF60, // full-width alphanumerics and symbols
		r >= 0xFFE0 && r <= 0xFFE6,
		r >= 0x20000 && r <= 0x3FFFD: // CJK extension
		return true
	}
	return false
}

// single is the display of a single value (or no value).
func single(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return values[0]
}

// WriteSummary prints the compared scope and the attributes that were not compared.
// It also states what was not looked at so that "no differences" has a clear meaning. excluded is the exclude setting of the config.
func WriteSummary(w io.Writer, opt plan.Options, sum Summary, excluded []string) {
	fmt.Fprintln(w, "\n--- summary ---")
	fmt.Fprintf(w, "compared objects : %s\n", kindCounts(opt, sum))
	fmt.Fprintln(w, "differences:")
	fmt.Fprintf(w, "  ONLY_SOURCE : %d   (only in source: not cloned yet)\n", sum.Differences[OnlySource])
	fmt.Fprintf(w, "  ONLY_TARGET : %d   (only in target: not in source)\n", sum.Differences[OnlyTarget])
	fmt.Fprintf(w, "  DIFF        : %d   (in both, but attribute values differ)\n", sum.Differences[Differ])
	if sum.CaseOnly > 0 {
		fmt.Fprintf(w, "                    of which case only: %d\n", sum.CaseOnly)
	}
	if sum.Tracking {
		fmt.Fprintf(w, "  RENAMED     : %d   (same object, but its DN differs on target: renamed/moved)\n", sum.Differences[Renamed])
		if sum.Differences[Replaced] > 0 {
			fmt.Fprintf(w, "  REPLACED    : %d   (same DN, but a different object than the one cloned)\n", sum.Differences[Replaced])
		}
		if sum.Implied > 0 {
			fmt.Fprintf(w, "                    not listed: %d entries moved along with a renamed/moved parent OU\n", sum.Implied)
		}
	}
	switch {
	case sum.Identity:
		fmt.Fprintln(w, "rename/move check: on (objectGUID preserved: the target holds the same objectGUID as the source, no mapping file needed)")
	case sum.Tracking:
		fmt.Fprintf(w, "rename/move check: on (%d GUID pairs in the mapping file)\n", sum.TrackedPairs)
	default:
		fmt.Fprintln(w, "rename/move check: off (set [state] file in the config; clone records the mapping)")
	}
	fmt.Fprintln(w, "compared attributes:")
	var masked []string
	for _, kind := range attrs.SortedKinds(opt.Kinds) {
		var names []string
		for _, n := range opt.Attrs[kind] {
			if opt.Masker.Masked(n) {
				masked = appendUnique(masked, n)
				continue
			}
			names = append(names, n)
		}
		fmt.Fprintf(w, "  %-5s: %s\n", kind, strings.Join(names, ", "))
	}
	fmt.Fprintln(w, "not compared:")
	fmt.Fprintf(w, "  masked (config [mask])        : %s\n", orNone(masked))
	fmt.Fprintf(w, "  excluded (config exclude)     : %s\n", orNone(excluded))
	fmt.Fprintf(w, "  never compared                : password attributes (%s),\n", strings.Join(opt.P().PasswordAttrs, ", "))
	fmt.Fprintln(w, "                                  and any attribute not listed above")
}

func kindCounts(opt plan.Options, sum Summary) string {
	var parts []string
	for _, kind := range attrs.SortedKinds(opt.Kinds) {
		parts = append(parts, fmt.Sprintf("%s=%d", kind, sum.Compared[kind]))
	}
	return strings.Join(parts, " ")
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return list
		}
	}
	return append(list, v)
}

func orNone(list []string) string {
	if len(list) == 0 {
		return "(none)"
	}
	return strings.Join(list, ", ")
}

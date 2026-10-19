package diff

import (
	"fmt"
	"io"
	"strings"
)

// DefaultMaxValues is the default cap on values shown per attribute and direction for a multi-valued difference:
// none. A cut list could hide the one removal a test is looking for; -max-values shortens it on request.
const DefaultMaxValues = 0

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
	if d.Kind == Unmarked {
		fmt.Fprintln(w, "            no marker: recreated, marker removed, or added to the source after the clone")
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

package diff

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/plan"
)

// WriteSummary prints the compared scope and the attributes that were not compared.
// It also states what was not looked at so that "no differences" has a clear meaning. excluded is the exclude setting of the config.
func WriteSummary(w io.Writer, job plan.Job, sum Summary, excluded []string) {
	fmt.Fprintln(w, "\n--- summary ---")
	fmt.Fprintf(w, "compared objects : %s\n", kindCounts(job, sum))
	fmt.Fprintln(w, "differences:")
	fmt.Fprintf(w, "  ONLY_SOURCE : %d   (only in source: not cloned yet)\n", sum.Differences[OnlySource])
	fmt.Fprintf(w, "  ONLY_TARGET : %d   (only in target: not in source)\n", sum.Differences[OnlyTarget])
	fmt.Fprintf(w, "  DIFF        : %d   (in both, but attribute values differ)\n", sum.Differences[Differ])
	if sum.CaseOnly > 0 {
		fmt.Fprintf(w, "                    of which case only: %d\n", sum.CaseOnly)
	}
	if sum.Matching != "" {
		fmt.Fprintf(w, "  RENAMED     : %d   (same object, but its DN differs on target: renamed/moved)\n", sum.Differences[Renamed])
		if sum.Differences[Replaced] > 0 {
			fmt.Fprintf(w, "  REPLACED    : %d   (same DN, but a different object than the one cloned)\n", sum.Differences[Replaced])
		}
		if sum.Differences[Unmarked] > 0 {
			fmt.Fprintf(w, "  UNMARKED    : %d   (same DN, no marker: recreated, or added to the source after the clone)\n", sum.Differences[Unmarked])
		}
		if sum.Implied > 0 {
			fmt.Fprintf(w, "                    not listed: %d entries moved along with a renamed/moved parent OU\n", sum.Implied)
		}
		if sum.Duplicates > 0 {
			fmt.Fprintf(w, "                    %d objects were found more than once (a copied marker or identifier); the first was used\n", sum.Duplicates)
		}
		fmt.Fprintf(w, "rename/move check: on (%s)\n", sum.Matching)
	} else {
		fmt.Fprintln(w, "rename/move check: off ([mapping] mode is off, or nothing to match by)")
	}
	if sum.Referenced > 0 {
		fmt.Fprintf(w, "referenced objects outside the scope compared: %d (without their own references)\n", sum.Referenced)
	}
	if len(sum.NotCompared) > 0 {
		names := make([]string, 0, len(sum.NotCompared))
		for n := range sum.NotCompared {
			names = append(names, n)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, n := range names {
			parts = append(parts, fmt.Sprintf("%s %d", n, sum.NotCompared[n]))
		}
		fmt.Fprintf(w, "references not compared (clone cannot write them: the target lacks their entries): %s\n", strings.Join(parts, ", "))
	}
	fmt.Fprintln(w, "compared attributes:")
	var masked []string
	for _, k := range job.Kinds {
		var names []string
		for _, n := range k.Attrs {
			if job.Masker.Masked(n) {
				masked = appendUnique(masked, n)
				continue
			}
			names = append(names, n)
		}
		fmt.Fprintf(w, "  %-5s: %s\n", k.Name, strings.Join(names, ", "))
	}
	fmt.Fprintln(w, "not compared:")
	fmt.Fprintf(w, "  masked (config [mask])        : %s\n", orNone(masked))
	fmt.Fprintf(w, "  excluded (config exclude)     : %s\n", orNone(excluded))
	fmt.Fprintf(w, "  never compared                : password attributes (%s),\n", strings.Join(job.Profile.PasswordAttrs, ", "))
	fmt.Fprintln(w, "                                  and any attribute not listed above")
}

func kindCounts(job plan.Job, sum Summary) string {
	var parts []string
	for _, k := range job.Kinds {
		parts = append(parts, fmt.Sprintf("%s=%d", k.Name, sum.Compared[k.Name]))
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

package diff

import (
	"fmt"
	"io"
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
		id := job.Profile.Identity.Attr()
		fmt.Fprintf(w, "rename/move check: on (%s preserved: the target holds the same %s as the source, no mapping file needed)\n", id, id)
	case sum.Tracking:
		fmt.Fprintf(w, "rename/move check: on (%d %s pairs in the mapping file)\n", sum.TrackedPairs, job.Profile.Identity.Attr())
	default:
		fmt.Fprintln(w, "rename/move check: off (set [mapping] file in the config; clone records the mapping)")
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

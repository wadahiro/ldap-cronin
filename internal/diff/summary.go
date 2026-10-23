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
	if sum.Holders > 0 {
		fmt.Fprintf(w, "groups outside the scope holding its entries compared: %d (their values naming the scope)\n", sum.Holders)
	}
	if len(sum.Unheld) > 0 {
		plan.WriteCounts(w, "groups outside the scope holding its entries, not compared (clone leaves them as they are)", sum.Unheld)
	}
	if sum.Placeholders > 0 {
		fmt.Fprintf(w, "placeholders under base_dn not compared (clone created them for entries the source did not return): %d\n", sum.Placeholders)
	}
	if len(sum.NotCloned) > 0 {
		plan.WriteCounts(w, "not compared (of no kind, or built-in: clone does not copy it)", sum.NotCloned)
	}
	if len(sum.NotComparedWhy) > 0 {
		plan.WriteCounts(w, "references not compared (clone cannot write them: the target lacks what they name)", sum.NotComparedWhy)
	}
	if job.ACL {
		fmt.Fprintln(w, "ACLs compared: each object's owner, group, protected flag and explicit ACEs (nTSecurityDescriptor; the inherited ACEs are each server's)")
	}
	fmt.Fprintln(w, "compared attributes:")
	compared, masked := comparedAttributes(job)
	for _, k := range job.Kinds {
		if job.AllWritable {
			fmt.Fprintf(w, "  %-5s: %d, every attribute a client can write on %s (list-attrs -config lists them)\n", k.Name, len(compared[k.Name]), k.Class)
			continue
		}
		fmt.Fprintf(w, "  %-5s: %s\n", k.Name, strings.Join(compared[k.Name], ", "))
	}
	fmt.Fprintln(w, "not compared:")
	writeList(w, "masked (config [mask])", masked)
	writeList(w, "excluded (config exclude)", excluded)
	writeList(w, "credentials (clone never copies them)", job.Profile.PasswordAttrs)
	if job.AllWritable {
		fmt.Fprintln(w, "  and what only the server writes, or the target's schema lacks")
	} else {
		fmt.Fprintln(w, "  and any attribute not listed above")
	}
}

// comparedAttributes returns the attributes compared per kind, and the masked ones left out of them (one masked on a
// kind's entries only with the kind: "mail (user)").
func comparedAttributes(job plan.Job) (compared map[string][]string, masked []string) {
	compared = map[string][]string{}
	for _, k := range job.Kinds {
		names := []string{}
		for _, n := range k.Attrs {
			if job.Masker.MaskedIn(k.Name, n) {
				if job.Masker.Masked(n) {
					masked = appendUnique(masked, n)
				} else {
					masked = appendUnique(masked, n+" ("+k.Name+")") // masked on this kind's entries only
				}
				continue
			}
			names = append(names, n)
		}
		compared[k.Name] = names
	}
	return compared, masked
}

// writeList prints one attribute per line under a heading, so a long list stays readable.
func writeList(w io.Writer, heading string, names []string) {
	if len(names) == 0 {
		fmt.Fprintf(w, "  %s: (none)\n", heading)
		return
	}
	fmt.Fprintf(w, "  %s:\n", heading)
	for _, n := range names {
		fmt.Fprintf(w, "    %s\n", n)
	}
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

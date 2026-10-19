package diff

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"unicode/utf8"

	"github.com/wadahiro/ldap-cronin/internal/plan"
)

// JSONVersion is the version of the JSON Lines output; it changes when a field changes meaning or goes away (a new
// field does not change it).
const JSONVersion = 1

// jsonDifference is one line of the JSON output. Values are never cut short. When a value of the attribute is not
// UTF-8 (a binary attribute), every value of the line is base64 and Base64 is true.
type jsonDifference struct {
	Kind string `json:"kind"`
	DN   string `json:"dn"`
	Attr string `json:"attr,omitempty"`
	// A single-valued attribute: the values on each side (empty when the side has none).
	Source *[]string `json:"source,omitempty"`
	Target *[]string `json:"target,omitempty"`
	// A multi-valued attribute: the values only one side holds.
	OnlySource *[]string `json:"only_source,omitempty"`
	OnlyTarget *[]string `json:"only_target,omitempty"`
	CaseOnly   bool      `json:"case_only,omitempty"`
	Base64     bool      `json:"base64,omitempty"`
	// RENAMED
	TargetDN string `json:"target_dn,omitempty"`
	Renamed  bool   `json:"renamed,omitempty"`
	Moved    bool   `json:"moved,omitempty"`
}

// JSON writes the differences as JSON Lines: one object per difference, then one summary object (kind SUMMARY).
// It holds nothing between lines, so it streams like the text output.
type JSON struct{ enc *json.Encoder }

// NewJSON writes to w.
func NewJSON(w io.Writer) *JSON {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // DNs and values are printed as they are, not with < for <
	return &JSON{enc: enc}
}

// Difference writes one difference.
func (j *JSON) Difference(d Difference) error {
	out := jsonDifference{Kind: string(d.Kind), DN: d.DN}
	switch d.Kind {
	case Renamed:
		out.TargetDN, out.Renamed, out.Moved = d.TargetDN, d.RDNRenamed, d.Moved
	case Differ:
		out.Attr, out.CaseOnly = d.Attr, d.CaseOnly
		lists := [][]string{d.Source, d.Target}
		if d.Multi {
			lists = [][]string{d.OnlySource, d.OnlyTarget}
		}
		out.Base64 = !allUTF8(lists...)
		a, b := encodeValues(lists[0], out.Base64), encodeValues(lists[1], out.Base64)
		if d.Multi {
			out.OnlySource, out.OnlyTarget = &a, &b
		} else {
			out.Source, out.Target = &a, &b
		}
	}
	return j.enc.Encode(out)
}

func allUTF8(lists ...[]string) bool {
	for _, l := range lists {
		for _, v := range l {
			if !utf8.ValidString(v) {
				return false
			}
		}
	}
	return true
}

// encodeValues returns values as the JSON carries them, never nil, so a side without values is [] rather than absent.
func encodeValues(values []string, b64 bool) []string {
	out := make([]string, len(values))
	for i, v := range values {
		if b64 {
			v = base64.StdEncoding.EncodeToString([]byte(v))
		}
		out[i] = v
	}
	return out
}

// jsonSummary is the last line: what WriteSummary prints, as data.
type jsonSummary struct {
	Kind        string         `json:"kind"`
	Version     int            `json:"version"`
	Compared    map[string]int `json:"compared"`
	Differences map[string]int `json:"differences"`
	CaseOnly    int            `json:"case_only"`
	// RenameCheck is how renames and moves were detected; empty when they were not.
	RenameCheck string `json:"rename_check"`
	Implied     int    `json:"implied"`
	Duplicates  int    `json:"duplicates"`
	Referenced  int    `json:"referenced"`
	// NotCloned counts the entries of no kind under base_dn, per structural object class.
	NotCloned map[string]int `json:"not_cloned"`
	// ReferencesNotCompared counts, per attribute, the source values clone cannot write.
	ReferencesNotCompared map[string]int      `json:"references_not_compared"`
	ComparedAttributes    map[string][]string `json:"compared_attributes"`
	Masked                []string            `json:"masked"`
	Excluded              []string            `json:"excluded"`
	Credentials           []string            `json:"credentials"`
}

// Summary writes the summary line. excluded is the exclude setting of the config.
func (j *JSON) Summary(job plan.Job, sum Summary, excluded []string) error {
	compared, masked := comparedAttributes(job)
	out := jsonSummary{
		Kind: "SUMMARY", Version: JSONVersion, Compared: map[string]int{}, Differences: map[string]int{},
		CaseOnly: sum.CaseOnly, RenameCheck: sum.Matching, Implied: sum.Implied, Duplicates: sum.Duplicates,
		Referenced: sum.Referenced, NotCloned: orEmpty(sum.NotCloned), ReferencesNotCompared: orEmpty(sum.NotCompared),
		ComparedAttributes: compared, Masked: nonNil(masked), Excluded: nonNil(excluded), Credentials: nonNil(job.Profile.PasswordAttrs),
	}
	for _, k := range job.Kinds {
		out.Compared[k.Name] = sum.Compared[k.Name]
	}
	for _, k := range []Kind{OnlySource, OnlyTarget, Differ, Renamed, Replaced, Unmarked} {
		out.Differences[string(k)] = sum.Differences[k]
	}
	return j.enc.Encode(out)
}

func orEmpty(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

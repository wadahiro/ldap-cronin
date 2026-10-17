package profile

import (
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/fakedir"
)

const schemaNC = "CN=Schema,CN=Configuration,DC=ad,DC=example,DC=com"

func schemaWith(attrs map[string]map[string][]string) *fakedir.Dir {
	d := fakedir.New(schemaNC)
	d.Put("", map[string][]string{"schemaNamingContext": {schemaNC}})
	for name, a := range attrs {
		a["objectClass"] = []string{"top", "attributeSchema"}
		a["lDAPDisplayName"] = []string{name}
		d.Put("CN="+name+","+schemaNC, a)
	}
	return d
}

func TestADChecksTheMarkerAttributeInTheTargetSchema(t *testing.T) {
	d := schemaWith(map[string]map[string][]string{
		"adminDisplayName": {"attributeSyntax": {"2.5.5.12"}, "isSingleValued": {"TRUE"}, "rangeUpper": {"256"}, "searchFlags": {"1"}},
		"unindexed":        {"attributeSyntax": {"2.5.5.12"}, "isSingleValued": {"TRUE"}, "searchFlags": {"0"}},
		"short":            {"attributeSyntax": {"2.5.5.12"}, "isSingleValued": {"TRUE"}, "rangeUpper": {"20"}},
		"multi":            {"attributeSyntax": {"2.5.5.12"}, "isSingleValued": {"FALSE"}},
		"number":           {"attributeSyntax": {"2.5.5.9"}, "isSingleValued": {"TRUE"}},
	})
	ctx := context.Background()
	if w, err := AD.MarkerCheck.CheckMarker(ctx, d, "adminDisplayName", 53); err != nil || w != "" {
		t.Fatalf("%q %v", w, err)
	}
	if w, err := AD.MarkerCheck.CheckMarker(ctx, d, "unindexed", 53); err != nil || !strings.Contains(w, "not indexed") {
		t.Fatalf("%q %v", w, err)
	}
	for attr, want := range map[string]string{"short": "at most 20", "multi": "multi-valued", "number": "does not hold strings", "absent": "not in the target schema"} {
		if _, err := AD.MarkerCheck.CheckMarker(ctx, d, attr, 53); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", attr, want, err)
		}
	}
}

//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// A source AD with an attribute of its own (a schema extension) that the target lacks: clone refuses to start,
// naming the attribute, and writes nothing.
func TestCloneRefusesAnAttributeTheTargetSchemaLacks(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	name := fmt.Sprintf("acmeProbe%06d", runID)
	ctx := context.Background()
	src, dst := dial(t, srcURL), dial(t, dstURL)
	schema := "CN=Schema,CN=Configuration," + realmDN
	if err := src.Add(ctx, directory.Entry{DN: "CN=" + name + "," + schema, Attrs: map[string][]string{
		"objectClass": {"attributeSchema"}, "cn": {name}, "lDAPDisplayName": {name},
		"attributeID": {fmt.Sprintf("1.3.6.1.4.1.99999.9.%d", runID)}, "attributeSyntax": {"2.5.5.12"}, "oMSyntax": {"64"},
		"isSingleValued": {"TRUE"},
	}}); err != nil {
		t.Fatalf("extend the source schema: %v", err)
	}
	scope := fmt.Sprintf("OU=Schema%06d,%s", runID, realmDN)
	if err := src.Add(ctx, directory.Entry{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("Schema%06d", runID)}}}); err != nil {
		t.Fatal(err)
	}
	job := planOptionsFor(t, scope)
	for i := range job.Kinds {
		job.Kinds[i].Attrs = append(job.Kinds[i].Attrs, name)
	}
	_, err := clone.Run(ctx, src, dst, job, clone.Options{UserPassword: fixedPw, Workers: 2}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "target schema lacks") {
		t.Fatalf("clone must refuse before writing: %v", err)
	}
	if e, err := dst.Get(ctx, scope, []string{"ou"}); err != nil || e != nil {
		t.Fatalf("nothing may be written: %v %v", e, err)
	}
}

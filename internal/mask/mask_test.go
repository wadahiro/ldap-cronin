package mask

import (
	"reflect"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

func TestApplyReplacesOnlyMaskedAttributesAndKeepsInput(t *testing.T) {
	in := directory.Entry{DN: "cn=a", Attrs: map[string][]string{"mail": {"a@x", "b@x"}, "sn": {"S"}}}
	out := New("***", []string{"MAIL"}).Apply(in)
	if !reflect.DeepEqual(out.Attrs["mail"], []string{"***"}) || out.Attrs["sn"][0] != "S" {
		t.Fatalf("%v", out.Attrs)
	}
	if len(in.Attrs["mail"]) != 2 {
		t.Fatal("input mutated")
	}
}

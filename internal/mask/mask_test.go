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

// An attribute of a kind's list is masked on that kind's entries only; the global ones on every entry.
func TestKindsAddToTheGlobalMask(t *testing.T) {
	m := New("***", []string{"telephoneNumber"}).WithKinds(map[string][]string{"user": {"Mail"}})
	e := directory.Entry{DN: "cn=a", Attrs: map[string][]string{"mail": {"a@x"}, "telephoneNumber": {"1"}}}
	if u := m.ApplyIn("user", e); u.Attrs["mail"][0] != "***" || u.Attrs["telephoneNumber"][0] != "***" {
		t.Errorf("user: %v", u.Attrs)
	}
	if g := m.ApplyIn("group", e); g.Attrs["mail"][0] != "a@x" || g.Attrs["telephoneNumber"][0] != "***" {
		t.Errorf("group: %v", g.Attrs)
	}
	if n := m.Apply(e); n.Attrs["mail"][0] != "a@x" || m.Masked("mail") || !m.MaskedIn("USER", "MAIL") {
		t.Errorf("no kind: %v", n.Attrs)
	}
}

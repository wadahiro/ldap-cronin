package compare

import (
	"reflect"
	"testing"
)

func TestEqual(t *testing.T) {
	cases := []struct {
		name, attr string
		a, b       []string
		want       bool
	}{
		{"order ignored", "description", []string{"a", "b"}, []string{"b", "a"}, true},
		{"strings are case-sensitive", "description", []string{"a"}, []string{"A"}, false},
		{"objectClass case-insensitive", "objectClass", []string{"User"}, []string{"user"}, true},
		{"member DN escape and case", "member", []string{`CN=Doe\, J,DC=x`}, []string{`cn=doe\2C j,dc=X`}, true},
		{"uac ignores lockout bit", "userAccountControl", []string{"528"}, []string{"512"}, true},
		{"uac disabled differs", "userAccountControl", []string{"514"}, []string{"512"}, false},
		{"never expires has two forms", "accountExpires", []string{"0"}, []string{"9223372036854775807"}, true},
		{"different count", "mail", []string{"a"}, []string{"a", "b"}, false},
	}
	for _, c := range cases {
		if got := Equal(c.attr, c.a, c.b); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestSetDiffReturnsValuesInSortedOrderRegardlessOfInputOrder(t *testing.T) {
	a := []string{"CN=Zed,DC=x", "cn=alice,dc=x", "CN=Mike,DC=x", "CN=shared,DC=x"}
	b := []string{"CN=Yuki,DC=x", "CN=shared,DC=x", "cn=bob,dc=x"}
	onlyA, onlyB := SetDiff("member", true, a, b)
	wantA := []string{"cn=alice,dc=x", "CN=Mike,DC=x", "CN=Zed,DC=x"}
	wantB := []string{"cn=bob,dc=x", "CN=Yuki,DC=x"}
	if !reflect.DeepEqual(onlyA, wantA) || !reflect.DeepEqual(onlyB, wantB) {
		t.Fatalf("got %v / %v", onlyA, onlyB)
	}
	// Reordering the input does not change the result.
	revA := []string{a[3], a[2], a[1], a[0]}
	revB := []string{b[2], b[1], b[0]}
	rA, rB := SetDiff("member", true, revA, revB)
	if !reflect.DeepEqual(rA, wantA) || !reflect.DeepEqual(rB, wantB) {
		t.Fatalf("order depends on input: %v / %v", rA, rB)
	}
}

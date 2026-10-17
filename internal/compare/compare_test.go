package compare

import (
	"reflect"
	"testing"
)

func TestEqual(t *testing.T) {
	cases := []struct {
		name string
		n    Normalizer
		a, b []string
		want bool
	}{
		{"order ignored", nil, []string{"a", "b"}, []string{"b", "a"}, true},
		{"strings are case-sensitive", nil, []string{"a"}, []string{"A"}, false},
		{"case-insensitive when asked", CaseIgnore, []string{"User"}, []string{"user"}, true},
		{"DN escape and case", DN, []string{`CN=Doe\, J,DC=x`}, []string{`cn=doe\2C j,dc=X`}, true},
		{"different count", nil, []string{"a"}, []string{"a", "b"}, false},
		{"duplicates count", nil, []string{"a", "a"}, []string{"a", "b"}, false},
	}
	for _, c := range cases {
		if got := Equal(c.n, c.a, c.b); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestSetDiffReturnsValuesInSortedOrderRegardlessOfInputOrder(t *testing.T) {
	a := []string{"CN=Zed,DC=x", "cn=alice,dc=x", "CN=Mike,DC=x", "CN=shared,DC=x"}
	b := []string{"CN=Yuki,DC=x", "CN=shared,DC=x", "cn=bob,dc=x"}
	onlyA, onlyB := SetDiff(DN, a, b)
	wantA := []string{"cn=alice,dc=x", "CN=Mike,DC=x", "CN=Zed,DC=x"}
	wantB := []string{"cn=bob,dc=x", "CN=Yuki,DC=x"}
	if !reflect.DeepEqual(onlyA, wantA) || !reflect.DeepEqual(onlyB, wantB) {
		t.Fatalf("got %v / %v", onlyA, onlyB)
	}
	// Reordering the input does not change the result.
	revA := []string{a[3], a[2], a[1], a[0]}
	revB := []string{b[2], b[1], b[0]}
	rA, rB := SetDiff(DN, revA, revB)
	if !reflect.DeepEqual(rA, wantA) || !reflect.DeepEqual(rB, wantB) {
		t.Fatalf("order depends on input: %v / %v", rA, rB)
	}
}

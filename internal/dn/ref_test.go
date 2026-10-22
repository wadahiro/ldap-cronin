package dn

import "testing"

func TestSplitRef(t *testing.T) {
	for _, c := range []struct{ v, prefix, dn string }{
		{"CN=a,DC=x", "", "CN=a,DC=x"},
		{"B:0::CN=a,DC=x", "B:0::", "CN=a,DC=x"},
		{"B:8:0A0B0C0D:CN=a,DC=x", "B:8:0A0B0C0D:", "CN=a,DC=x"},
		{"S:5:a:b:c:CN=a\\, b,DC=x", "S:5:a:b:c:", "CN=a\\, b,DC=x"}, // colons inside the string
		{"S:3:日本語:CN=a,DC=x", "S:3:日本語:", "CN=a,DC=x"},               // a count of characters
		{"B:4:0A:CN=a,DC=x", "", "B:4:0A:CN=a,DC=x"},                 // the count does not fit
		{"B:x::CN=a", "", "B:x::CN=a"},
		{"B:0::", "", "B:0::"},
		{"", "", ""},
	} {
		p, d := SplitRef(c.v)
		if p != c.prefix || d != c.dn {
			t.Errorf("SplitRef(%q) = %q, %q; want %q, %q", c.v, p, d, c.prefix, c.dn)
		}
	}
}

func TestNormalizeRef(t *testing.T) {
	same := [][2]string{
		{"B:0::CN=A,DC=X", "cn=a,dc=x"},
		{"S:0::cn=a,dc=x", "CN=a,DC=x"},
		{"B:4:0a0b:CN=A,DC=X", "b:4:0A0B:cn=a,dc=x"},
	}
	for _, c := range same {
		if NormalizeRef(c[0]) != NormalizeRef(c[1]) {
			t.Errorf("%q and %q differ: %q, %q", c[0], c[1], NormalizeRef(c[0]), NormalizeRef(c[1]))
		}
	}
	differ := [][2]string{
		{"B:4:0A0B:CN=a,DC=x", "CN=a,DC=x"},
		{"B:4:0A0B:CN=a,DC=x", "B:4:0A0C:CN=a,DC=x"},
		{"S:1:a:CN=a,DC=x", "S:1:A:CN=a,DC=x"},
	}
	for _, c := range differ {
		if NormalizeRef(c[0]) == NormalizeRef(c[1]) {
			t.Errorf("%q and %q are the same", c[0], c[1])
		}
	}
	if RewrapRef("B:4:0A0B:CN=a,DC=x", "CN=b,DC=x") != "B:4:0A0B:CN=b,DC=x" || RewrapRef("CN=a,DC=x", "CN=b,DC=x") != "CN=b,DC=x" {
		t.Error("RewrapRef")
	}
}

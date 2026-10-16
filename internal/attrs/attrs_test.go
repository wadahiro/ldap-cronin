package attrs

import (
	"slices"
	"strings"
	"testing"
)

func has(list []string, name string) bool {
	return slices.ContainsFunc(list, func(s string) bool { return strings.EqualFold(s, name) })
}

func TestDefaultsExcludeExchangeExtensionAttributes(t *testing.T) {
	for _, kind := range Kinds {
		got, err := Resolve(kind, Override{})
		if err != nil {
			t.Fatal(err)
		}
		if has(got, "extensionAttribute1") || !has(got, "objectClass") {
			t.Fatalf("%s: %v", kind, got)
		}
	}
}

func TestExtraAddsAndExcludeRemovesButRequiredStays(t *testing.T) {
	got, err := Resolve(KindUser, Override{Extra: []string{"extensionAttribute1"}, Exclude: []string{"mail", "objectClass"}})
	if err != nil {
		t.Fatal(err)
	}
	if !has(got, "extensionAttribute1") || has(got, "mail") || !has(got, "objectClass") {
		t.Fatalf("%v", got)
	}
}

func TestIncludeReplacesDefaults(t *testing.T) {
	got, _ := Resolve(KindUser, Override{Include: map[string][]string{KindUser: {"sn"}}})
	if has(got, "mail") || !has(got, "sn") {
		t.Fatalf("%v", got)
	}
}

func TestUncloneableAttributeIsRejected(t *testing.T) {
	if _, err := Resolve(KindUser, Override{Extra: []string{"objectGUID"}}); err == nil {
		t.Fatal("expected error")
	}
}

func TestMaskForbiddenAttributes(t *testing.T) {
	for _, n := range []string{"sAMAccountName", "MEMBER", "objectClass", "countryCode"} {
		if IsMaskable(n) {
			t.Errorf("%s must not be maskable", n)
		}
	}
	if !IsMaskable("mail") {
		t.Error("mail must be maskable")
	}
}

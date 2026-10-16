package config

import (
	"strings"
	"testing"
)

const valid = `
[source]
url = "ldaps://src:636"
bind_dn = "CN=Administrator,CN=Users,DC=ad,DC=example,DC=com"
[target]
url = "ldap://dst:389"
bind_dn = "CN=Administrator,CN=Users,DC=ad,DC=example,DC=com"
[clone]
base_dn = "OU=IDM,DC=ad,DC=example,DC=com"
[mask]
attributes = ["mail"]
`

func withProfile(name string) string {
	return strings.Replace(valid, "[clone]", "[clone]\nprofile = \""+name+"\"", 1)
}

func TestParseAppliesDefaults(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Clone.Objects) != 3 || c.Clone.Workers != defaultWorkers || c.Mask.Value != defaultMaskValue {
		t.Fatalf("%+v", c)
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"domain root base":     strings.Replace(valid, "OU=IDM,DC=ad", "DC=ad", 1),
		"unmaskable attribute": strings.Replace(withProfile("ad"), `["mail"]`, `["sAMAccountName"]`, 1),
		"unknown field":        valid + "\n[bogus]\nx = 1\n",
		"same server":          strings.Replace(valid, "ldap://dst:389", "ldaps://src:636", 1),
		"bad scheme":           strings.Replace(valid, "ldap://dst:389", "http://dst", 1),
		"unclonable include":   withProfile("ad") + "\n[attributes]\nextra_include = [\"objectGUID\"]\n",
		"unknown profile":      withProfile("oracle"),
		"ad without DC root":   strings.Replace(withProfile("ad"), "OU=IDM,DC=ad,DC=example,DC=com", "ou=IDM,o=acme", 1),
		"unknown object":       strings.Replace(valid, "[clone]", "[clone]\nobjects = [\"computer\"]", 1),
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestAutoProfileDefersAttributeRulesToTheResolvedProfile(t *testing.T) {
	raw := valid + "\n[attributes]\nextra_include = [\"objectGUID\"]\n"
	c, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("with profile = auto the rules depend on the server, so Parse must not judge them: %v", err)
	}
	if _, err := c.PlanOptions(); err == nil {
		t.Fatal("PlanOptions assumes AD under auto, where objectGUID cannot be cloned")
	}
	ldapCfg, err := Parse([]byte(strings.Replace(raw, "[clone]", "[clone]\nprofile = \"ldap\"", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ldapCfg.PlanOptions(); err != nil {
		t.Fatalf("a generic LDAP server has no objectGUID rule: %v", err)
	}
}

func TestGenericBaseDNWithoutDCNeedsNoRootInTheConfig(t *testing.T) {
	raw := strings.Replace(valid, "OU=IDM,DC=ad,DC=example,DC=com", "ou=people,o=acme", 2)
	raw = strings.Replace(raw, "[clone]", "[clone]\nprofile = \"ldap\"", 1)
	if _, err := Parse([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	withRoot := strings.Replace(raw, "[clone]", "[clone]\nroot_dn = \"o=other\"", 1)
	if _, err := Parse([]byte(withRoot)); err == nil {
		t.Fatal("base_dn outside root_dn must be rejected")
	}
}

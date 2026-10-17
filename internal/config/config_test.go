package config

import (
	"strings"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/profile"
)

const valid = `
[source]
url = "ldaps://src:636"
bind_dn = "CN=Administrator,CN=Users,DC=ad,DC=example,DC=com"
[target]
url = "ldap://dst:389"
bind_dn = "CN=Administrator,CN=Users,DC=ad,DC=example,DC=com"
[scope]
base_dn = "OU=IDM,DC=ad,DC=example,DC=com"
[mask]
attributes = ["mail"]
`

func withProfile(name string) string {
	return strings.Replace(valid, "[scope]", "[scope]\nprofile = \""+name+"\"", 1)
}

func TestParseAppliesDefaults(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Scope.Objects) != 3 || c.Run.Workers != defaultWorkers || c.Mask.Value != defaultMaskValue {
		t.Fatalf("%+v", c)
	}
	if c.Source.Timeout() != defaultTimeout || c.Target.Timeout() != defaultTimeout {
		t.Fatalf("timeouts %v %v", c.Source.Timeout(), c.Target.Timeout())
	}
}

func TestParseReadsTimeouts(t *testing.T) {
	raw := strings.Replace(valid, "[target]", "timeout = \"30s\"\n[target]", 1)
	raw = strings.Replace(raw, "[scope]", "timeout = \"0\"\n[scope]", 1)
	c, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if c.Source.Timeout() != 30*time.Second || c.Target.Timeout() != 0 {
		t.Fatalf("timeouts %v %v", c.Source.Timeout(), c.Target.Timeout())
	}
	if _, err := Parse([]byte(strings.Replace(valid, "[target]", "timeout = \"soon\"\n[target]", 1))); err == nil {
		t.Fatal("a malformed timeout was accepted")
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
		"unknown object":       strings.Replace(valid, "[scope]", "[scope]\nobjects = [\"computer\"]", 1),
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
	if _, err := c.JobFor(profile.AD); err == nil {
		t.Fatal("once the server is known to be AD, objectGUID cannot be cloned")
	}
	ldapCfg, err := Parse([]byte(strings.Replace(raw, "[scope]", "[scope]\nprofile = \"ldap\"", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ldapCfg.JobFor(profile.LDAP); err != nil {
		t.Fatalf("a generic LDAP server has no objectGUID rule: %v", err)
	}
}

func TestGenericBaseDNWithoutDCNeedsNoRootInTheConfig(t *testing.T) {
	raw := strings.Replace(valid, "OU=IDM,DC=ad,DC=example,DC=com", "ou=people,o=acme", 2)
	raw = strings.Replace(raw, "[scope]", "[scope]\nprofile = \"ldap\"", 1)
	if _, err := Parse([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	withRoot := strings.Replace(raw, "[scope]", "[scope]\nroot_dn = \"o=other\"", 1)
	if _, err := Parse([]byte(withRoot)); err == nil {
		t.Fatal("base_dn outside root_dn must be rejected")
	}
}

func TestRenamedSectionsSayWhereTheirKeysWent(t *testing.T) {
	for old, now := range map[string]string{"[clone]": "[scope]", "[state]": "[mapping]", "[clone.filters]": "[scope.filters]"} {
		_, err := Parse([]byte(valid + "\n" + old + "\n"))
		if err == nil || !strings.Contains(err.Error(), now) {
			t.Errorf("%s: %v", old, err)
		}
	}
}

func TestJobFollowsTheProfileOrderAndAddsTheSystemFilter(t *testing.T) {
	c, err := Parse([]byte(strings.Replace(valid, "[scope]", "[scope]\nobjects = [\"user\", \"ou\"]", 1)))
	if err != nil {
		t.Fatal(err)
	}
	c.Scope.Filters = map[string]string{"user": "(department=IT)"}
	job, err := c.JobFor(profile.AD)
	if err != nil {
		t.Fatal(err)
	}
	if len(job.Kinds) != 2 || job.Kinds[0].Name != "ou" || job.Kinds[1].Name != "user" {
		t.Fatalf("kinds must follow the profile, not the config order: %+v", job.Kinds)
	}
	if f := job.Kinds[1].Filter; f != "(&(department=IT)(!(isCriticalSystemObject=TRUE)))" {
		t.Fatalf("filter %q", f)
	}
}

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
	if len(c.Scope.Objects) != 0 || c.Run.Workers != defaultWorkers || c.Mask.Value != DefaultMaskValue {
		t.Fatalf("%+v", c)
	}
	if c.Source.Timeout() != DefaultTimeout || c.Target.Timeout() != DefaultTimeout {
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
		"domain root base":           strings.Replace(valid, "OU=IDM,DC=ad", "DC=ad", 1),
		"unmaskable attribute":       strings.Replace(withProfile("ad"), `["mail"]`, `["sAMAccountName"]`, 1),
		"unknown field":              valid + "\n[bogus]\nx = 1\n",
		"same server":                strings.Replace(valid, "ldap://dst:389", "ldaps://src:636", 1),
		"bad scheme":                 strings.Replace(valid, "ldap://dst:389", "http://dst", 1),
		"unclonable include":         withProfile("ad") + "\n[attributes]\nextra_include = [\"objectGUID\"]\n",
		"unknown profile":            withProfile("oracle"),
		"unknown object":             strings.Replace(valid, "[scope]", "[scope]\nobjects = [\"printer\"]", 1),
		"unknown mode":               valid + "\n[attributes]\nmode = \"everything\"\n",
		"all with a list":            valid + "\n[attributes]\nmode = \"all\"\nextra_include = [\"proxyAddresses\"]\n",
		"all with include":           valid + "\n[attributes]\nmode = \"all\"\n[attributes.include]\nuser = [\"mail\"]\n",
		"unknown configuration_refs": strings.Replace(valid, "[scope]", "[scope]\nconfiguration_refs = \"create\"", 1),
		"a dump with a server":       strings.Replace(valid, "[source]", "[source]\nldif = \"prod.ldif\"", 1),
		"a dump as the target":       strings.Replace(valid, "[target]", "[target]\nldif = \"prod.ldif\"", 1),
		"a lab as the source":        strings.Replace(valid, "[target]", "[source.lab]\n[target]", 1),
		"fast_password over LDAP":    strings.Replace(valid, "[scope]", "[target.lab]\nfast_password = true\n[scope]", 1),
		"native with configuration_refs": strings.Replace(valid, "[scope]",
			"[target.lab]\nnative = true\n[scope]\nconfiguration_refs = \"clone\"", 1),
		"an EC2 key on docker": strings.Replace(valid, "[scope]", "[target.lab]\nregion = \"ap-northeast-1\"\n[scope]", 1),
		"an unknown platform":  strings.Replace(valid, "[scope]", "[target.lab]\nplatform = \"azure\"\n[scope]", 1),
		"EC2 without a subnet": strings.Replace(valid, "[scope]", "[target.lab]\nplatform = \"ec2\"\nregion = \"r\"\ninstance_profile = \"p\"\n[scope]", 1),
		"EC2 native":           strings.Replace(valid, "[scope]", "[target.lab]\n"+ec2Lab+"native = true\n[scope]", 1),
		"EC2 with an image":    strings.Replace(valid, "[scope]", "[target.lab]\n"+ec2Lab+"image = \"x\"\n[scope]", 1),
		"EC2 unknown windows":  strings.Replace(valid, "[scope]", "[target.lab]\n"+ec2Lab+"windows = \"2012\"\n[scope]", 1),
		"configuration_refs without references = clone": strings.Replace(valid, "[scope]",
			"[scope]\nreferences = \"existing\"\nconfiguration_refs = \"clone\"", 1),
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	dumped := "[source]\nldif = \"prod.ldif\"\n" + valid[strings.Index(valid, "[target]"):]
	if _, err := Parse([]byte(dumped)); err != nil {
		t.Errorf("a dump as the source needs no url nor bind_dn: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(valid, "[scope]", "[scope]\nconfiguration_refs = \"clone\"", 1))); err != nil {
		t.Errorf("configuration_refs = clone with the default references: %v", err)
	}
}

// [target.lab] names the lab the target is; native = true makes clone write it directly.
func TestTargetLabSaysWhichLabAndHowItIsWritten(t *testing.T) {
	c, err := Parse([]byte(strings.Replace(valid, "[scope]", "[target.lab]\ninstance = \"dev2\"\n[scope]", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Target.Lab == nil || c.Target.Lab.Instance != "dev2" || c.NativeLab() != nil {
		t.Fatalf("a lab cloned over LDAP: %+v", c.Target.Lab)
	}
	c, err = Parse([]byte(strings.Replace(valid, "[scope]", "[target.lab]\nnative = true\nfast_password = true\n[scope]", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if l := c.NativeLab(); l == nil || !l.FastPassword {
		t.Fatalf("a native lab: %+v", c.Target.Lab)
	}
	if c, _ := Parse([]byte(valid)); c.Target.Lab != nil || c.NativeLab() != nil {
		t.Fatal("without the section the target is a server")
	}
	if c.Target.Lab.OnEC2() {
		t.Fatal("docker is the default platform")
	}
	c, err = Parse([]byte(strings.Replace(valid, "[scope]", "[target.lab]\n"+ec2Lab+"windows = \"2025\"\ninstance_type = \"m5.xlarge\"\n[scope]", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if l := c.Target.Lab; !l.OnEC2() || l.Region != "ap-northeast-1" || l.Windows != "2025" || l.InstanceType != "m5.xlarge" {
		t.Fatalf("an EC2 lab: %+v", l)
	}
}

// ec2Lab is the least an EC2 lab needs.
const ec2Lab = "platform = \"ec2\"\nregion = \"ap-northeast-1\"\nsubnet = \"subnet-0123\"\ninstance_profile = \"ldap-cronin-lab\"\n"

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

func TestMappingAutoResolvesPerProfile(t *testing.T) {
	cases := []struct {
		mapping, mode, attr string
	}{
		{"", MappingMarker, "adminDisplayName"},
		{`attribute = "extensionAttribute15"`, MappingMarker, "extensionAttribute15"},
		{`mode = "off"`, MappingOff, ""},
		{`mode = "file"`, MappingFile, ""},
	}
	for _, c := range cases {
		cfg, err := Parse([]byte(valid + "[mapping]\n" + c.mapping + "\n"))
		if err != nil {
			t.Fatalf("%q: %v", c.mapping, err)
		}
		mode, attr, err := cfg.MappingFor(profile.AD)
		if err != nil || mode != c.mode || attr != c.attr {
			t.Fatalf("%q: %s %s %v", c.mapping, mode, attr, err)
		}
	}
	cfg, _ := Parse([]byte(valid))
	if mode, _, err := cfg.MappingFor(profile.LDAP); err != nil || mode != MappingPreserve {
		t.Fatalf("a generic server preserves entryUUID by default: %s %v", mode, err)
	}
	if !cfg.Mapping.Operational() {
		t.Fatal("operational attributes are copied by default")
	}
	if cfg, _ := Parse([]byte(valid + "[mapping]\nmode = \"file\"\n")); cfg.Mapping.File != defaultMappingFile {
		t.Fatalf("file defaults to %q: %q", defaultMappingFile, cfg.Mapping.File)
	}
}

func TestMappingRejectsKeysOfAnotherModeAndUnusableAttributes(t *testing.T) {
	for mapping, want := range map[string]string{
		`mode = "guess"`:                         "mode must be",
		`file = "m"`:                             "only with mode = \"file\"",
		"mode = \"off\"\nattribute = \"info\"":   "only with mode = \"marker\"",
		"mode = \"marker\"\noperational = false": "only with mode = \"preserve\"",
		`attribute = "description"`:              "in the attributes of",
		`attribute = "mail"`:                     "masked",
		`attribute = "objectGUID"`:               "managed by the server",
		`attribute = "whenChanged"`:              "managed by the server",
	} {
		_, err := Parse([]byte(withProfile("ad") + "[mapping]\n" + mapping + "\n"))
		if err == nil {
			cfg, _ := Parse([]byte(withProfile("ad") + "[mapping]\n" + mapping + "\n"))
			_, err = cfg.JobFor(profile.AD)
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want %q, got %v", mapping, want, err)
		}
	}
	cfg, _ := Parse([]byte(valid + "[mapping]\nmode = \"marker\"\n"))
	if _, _, err := cfg.MappingFor(profile.LDAP); err == nil || !strings.Contains(err.Error(), "needs an attribute") {
		t.Fatalf("marker on a generic server needs an attribute: %v", err)
	}
	cfg, _ = Parse([]byte(valid + "[mapping]\nmode = \"preserve\"\n"))
	if _, _, err := cfg.MappingFor(profile.AD); err == nil {
		t.Fatal("AD cannot preserve identifiers over LDAP")
	}
}

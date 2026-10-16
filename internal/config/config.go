// Package config loads and validates the TOML configuration. Passwords are never stored in the config file.
package config

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/wadahiro/ldap-cronin/internal/attrs"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/mask"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

const (
	defaultMaskValue = "********"
	defaultWorkers   = 8
)

type Endpoint struct {
	URL                string `toml:"url"`
	BindDN             string `toml:"bind_dn"`
	CAFile             string `toml:"ca_file"`
	InsecureSkipVerify bool   `toml:"insecure_skip_verify"`
	StartTLS           bool   `toml:"start_tls"`
}

type Clone struct {
	// Profile is the server type: auto (default; asks the source's root DSE), ad or ldap.
	Profile string `toml:"profile"`
	// RootDN is the top of the naming context that holds base_dn. Only needed when it cannot be derived
	// (a generic LDAP base_dn without DC= components that the server does not list in namingContexts).
	RootDN  string            `toml:"root_dn"`
	BaseDN  string            `toml:"base_dn"`
	Objects []string          `toml:"objects"`
	Filters map[string]string `toml:"filters"`
	Workers int               `toml:"workers"` // number of parallel connections; 1 means sequential
}

type Attributes struct {
	Include map[string][]string `toml:"include"`
	Extra   []string            `toml:"extra_include"`
	Exclude []string            `toml:"exclude"`
}

type Mask struct {
	Value      string   `toml:"value"`
	Attributes []string `toml:"attributes"`
}

// State is a local file shared by clone and diff.
type State struct {
	// File is the GUID mapping between source and target. When set, clone records it and diff
	// uses it to detect renames and moves on the target. Empty means unused.
	File string `toml:"file"`
}

type Config struct {
	State      State      `toml:"state"`
	Source     Endpoint   `toml:"source"`
	Target     Endpoint   `toml:"target"`
	Clone      Clone      `toml:"clone"`
	Attributes Attributes `toml:"attributes"`
	Mask       Mask       `toml:"mask"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

func Parse(raw []byte) (*Config, error) {
	var c Config
	dec := toml.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if len(c.Clone.Objects) == 0 {
		c.Clone.Objects = append([]string(nil), attrs.Kinds...)
	}
	if c.Clone.Workers == 0 {
		c.Clone.Workers = defaultWorkers
	}
	if c.Mask.Value == "" {
		c.Mask.Value = defaultMaskValue
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	for name, ep := range map[string]Endpoint{"source": c.Source, "target": c.Target} {
		u, err := url.Parse(ep.URL)
		if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" {
			return fmt.Errorf("[%s] url must be ldap:// or ldaps:// URL, got %q", name, ep.URL)
		}
		if ep.BindDN == "" {
			return fmt.Errorf("[%s] bind_dn is required", name)
		}
		if ep.StartTLS && u.Scheme == "ldaps" {
			return fmt.Errorf("[%s] start_tls cannot be combined with ldaps://", name)
		}
	}
	if strings.EqualFold(strings.TrimRight(c.Source.URL, "/"), strings.TrimRight(c.Target.URL, "/")) {
		return fmt.Errorf("source and target are the same server (%s)", c.Source.URL)
	}
	if c.Clone.BaseDN == "" {
		return fmt.Errorf("[clone] base_dn is required")
	}
	explicit, isExplicit, err := c.explicitProfile()
	if err != nil {
		return err
	}
	// Without DC= components the root is detected from the server later, so only reject what is certainly wrong here.
	root := c.Clone.RootDN
	if root == "" {
		root = dn.DomainRoot(c.Clone.BaseDN)
	}
	if (root == "" && isExplicit && explicit.Name == profile.NameAD) || (root != "" && (dn.Equal(c.Clone.BaseDN, root) || !dn.IsDescendant(c.Clone.BaseDN, root))) {
		return fmt.Errorf("[clone] base_dn must be an OU/container below the domain root (root_dn): %q", c.Clone.BaseDN)
	}
	if c.Clone.Workers < 1 {
		return fmt.Errorf("[clone] workers must be >= 1")
	}
	for _, o := range c.Clone.Objects {
		if !contains(attrs.Kinds, o) {
			return fmt.Errorf("[clone] objects: unknown kind %q (available: %s)", o, strings.Join(attrs.Kinds, ", "))
		}
	}
	for k := range c.Clone.Filters {
		if !contains(attrs.Kinds, k) {
			return fmt.Errorf("[clone.filters] unknown kind %q", k)
		}
	}
	// With profile = auto the attribute rules depend on the server, so they are checked in PlanOptionsFor.
	if isExplicit {
		return c.checkAttributes(explicit)
	}
	return nil
}

func (c *Config) checkAttributes(p profile.Profile) error {
	for _, a := range c.Mask.Attributes {
		if !attrs.IsMaskableFor(p, a) {
			return fmt.Errorf("[mask] attribute %q cannot be masked with a fixed string (identity, unique, DN-reference or non-string attribute)", a)
		}
	}
	for _, kind := range c.Clone.Objects {
		if _, err := attrs.ResolveFor(p, kind, c.override()); err != nil {
			return fmt.Errorf("[attributes] %s: %w", kind, err)
		}
	}
	return nil
}

// explicitProfile returns the profile named in the config. ok is false for auto (resolved against the server later).
func (c *Config) explicitProfile() (p profile.Profile, ok bool, err error) {
	if c.Clone.Profile == "" || strings.EqualFold(c.Clone.Profile, profile.NameAuto) {
		return profile.Profile{}, false, nil
	}
	p, err = profile.ByName(c.Clone.Profile)
	if err != nil {
		return p, false, fmt.Errorf("[clone] profile: %w", err)
	}
	return p, true, nil
}

// ProfileName is the profile name from the config (auto when not set).
func (c *Config) ProfileName() string {
	if c.Clone.Profile == "" {
		return profile.NameAuto
	}
	return c.Clone.Profile
}

func (c *Config) override() attrs.Override {
	return attrs.Override{Include: c.Attributes.Include, Extra: c.Attributes.Extra, Exclude: c.Attributes.Exclude}
}

// PlanOptions assembles the scope settings shared by clone and diff. With profile = auto it assumes AD;
// use PlanOptionsFor once the server type is known.
func (c *Config) PlanOptions() (plan.Options, error) {
	p, ok, err := c.explicitProfile()
	if err != nil {
		return plan.Options{}, err
	}
	if !ok {
		p = profile.AD
	}
	return c.PlanOptionsFor(p)
}

// PlanOptionsFor assembles the scope settings for a resolved profile.
func (c *Config) PlanOptionsFor(p profile.Profile) (plan.Options, error) {
	if err := c.checkAttributes(p); err != nil {
		return plan.Options{}, err
	}
	resolved := map[string][]string{}
	for _, kind := range attrs.Kinds {
		list, err := attrs.ResolveFor(p, kind, c.override())
		if err != nil {
			return plan.Options{}, err
		}
		resolved[kind] = list
	}
	return plan.Options{
		Profile: p,
		RootDN:  c.Clone.RootDN,
		BaseDN:  c.Clone.BaseDN,
		Kinds:   c.Clone.Objects,
		Filters: c.Clone.Filters,
		Attrs:   resolved,
		Masker:  mask.New(c.Mask.Value, c.Mask.Attributes),
	}, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

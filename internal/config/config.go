// Package config loads and validates the TOML configuration. Passwords are never stored in the config file.
package config

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/mask"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

const (
	defaultMaskValue = "********"
	defaultWorkers   = 8
	// defaultTimeout is generous because a single modify of a large group on Samba can take seconds; its job is only
	// to turn a hung server into an error.
	defaultTimeout = 2 * time.Minute
)

type Endpoint struct {
	URL                string `toml:"url"`
	BindDN             string `toml:"bind_dn"`
	CAFile             string `toml:"ca_file"`
	InsecureSkipVerify bool   `toml:"insecure_skip_verify"`
	StartTLS           bool   `toml:"start_tls"`
	// TimeoutText bounds each LDAP operation ("30s", "2m"; "0" for no limit). Read it through Timeout.
	TimeoutText string `toml:"timeout"`
	timeout     time.Duration
}

// Timeout is the parsed per-operation timeout.
func (e Endpoint) Timeout() time.Duration { return e.timeout }

// Scope is what clone and diff work on.
type Scope struct {
	// Profile is the server type: auto (default; asks the source's root DSE), ad or ldap.
	Profile string `toml:"profile"`
	// RootDN is the top of the naming context that holds base_dn. Only needed when it cannot be derived
	// (a generic LDAP base_dn without DC= components that the server does not list in namingContexts).
	RootDN  string            `toml:"root_dn"`
	BaseDN  string            `toml:"base_dn"`
	Objects []string          `toml:"objects"` // empty: every kind of the profile
	Filters map[string]string `toml:"filters"`
	// References is what is done with a reference to an entry outside the scope: clone (default), existing or
	// skip (see plan.RefsClone).
	References string `toml:"references"`
}

// Run holds the run-time settings shared by clone and diff.
type Run struct {
	Workers int `toml:"workers"` // number of parallel target connections; 1 means sequential
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

// Modes of [mapping]: how a target object tells which source object it was cloned from, so diff can report
// renames and moves made on the target.
const (
	MappingAuto     = "auto"     // preserve where the profile can, otherwise marker where it has a default attribute
	MappingPreserve = "preserve" // the target object gets the source identifier (OpenLDAP: relax control)
	MappingMarker   = "marker"   // clone writes the source key into an attribute of every object
	MappingFile     = "file"     // a local file of source and target identifiers
	MappingOff      = "off"
)

const defaultMappingFile = "mapping"

// Mapping says how target objects carry their source identity.
type Mapping struct {
	Mode string `toml:"mode"`
	// Attribute holds the marker; empty means the profile's default (adminDisplayName on AD).
	Attribute string `toml:"attribute"`
	// OperationalText (preserve only) also copies the operational attributes the profile lets an Add set
	// (createTimestamp, modifyTimestamp, creatorsName, modifiersName). Read it through Operational.
	OperationalText *bool `toml:"operational"`
	// File is the mapping file of mode = "file".
	File string `toml:"file"`
}

// Operational reports whether a preserving clone copies the operational attributes (default: yes, so the target
// looks like production).
func (m Mapping) Operational() bool { return m.OperationalText == nil || *m.OperationalText }

type Config struct {
	Source     Endpoint   `toml:"source"`
	Target     Endpoint   `toml:"target"`
	Scope      Scope      `toml:"scope"`
	Run        Run        `toml:"run"`
	Mapping    Mapping    `toml:"mapping"`
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

// renamed maps sections of earlier versions to where their keys live now. Old files are not read (there is no
// compatibility to keep at this stage), but they get an error that says what to change instead of "unknown field".
var renamed = map[string]string{
	"[clone]":         "[scope] (profile, root_dn, base_dn, objects) and [run] (workers)",
	"[clone.filters]": "[scope.filters]",
	"[state]":         "[mapping]",
}

func Parse(raw []byte) (*Config, error) {
	for _, line := range strings.Split(string(raw), "\n") {
		if now, ok := renamed[strings.TrimSpace(strings.SplitN(line, "#", 2)[0])]; ok {
			return nil, fmt.Errorf("parse config: section %s was renamed; use %s", strings.TrimSpace(strings.SplitN(line, "#", 2)[0]), now)
		}
	}
	var c Config
	dec := toml.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.Run.Workers == 0 {
		c.Run.Workers = defaultWorkers
	}
	if c.Mask.Value == "" {
		c.Mask.Value = defaultMaskValue
	}
	if c.Mapping.Mode == "" {
		c.Mapping.Mode = MappingAuto
	}
	if c.Mapping.Mode == MappingFile && c.Mapping.File == "" {
		c.Mapping.File = defaultMappingFile
	}
	for name, ep := range map[string]*Endpoint{"source": &c.Source, "target": &c.Target} {
		ep.timeout = defaultTimeout
		if ep.TimeoutText != "" {
			d, err := time.ParseDuration(ep.TimeoutText)
			if err != nil || d < 0 {
				return nil, fmt.Errorf("[%s] timeout must be a duration such as \"30s\" or \"2m\", got %q", name, ep.TimeoutText)
			}
			ep.timeout = d
		}
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	switch c.Scope.References {
	case "", plan.RefsClone, plan.RefsExisting, plan.RefsSkip:
	default:
		return fmt.Errorf("[scope] references must be %q, %q or %q, got %q", plan.RefsClone, plan.RefsExisting, plan.RefsSkip, c.Scope.References)
	}
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
	if c.Scope.BaseDN == "" {
		return fmt.Errorf("[scope] base_dn is required")
	}
	explicit, isExplicit, err := c.explicitProfile()
	if err != nil {
		return err
	}
	// Where the naming context starts is the profile's business and may need the server, so only reject what is
	// certainly wrong here: a base_dn that is the root it was given, or not below it.
	root := c.Scope.RootDN
	if root == "" {
		root = dn.DomainRoot(c.Scope.BaseDN)
	}
	if root != "" && (dn.Equal(c.Scope.BaseDN, root) || !dn.IsDescendant(c.Scope.BaseDN, root)) {
		return fmt.Errorf("[scope] base_dn must be an OU/container below the domain root (root_dn): %q", c.Scope.BaseDN)
	}
	if c.Run.Workers < 1 {
		return fmt.Errorf("[run] workers must be >= 1")
	}
	if err := c.Mapping.validate(); err != nil {
		return err
	}
	// With auto the profile is not known yet; a kind name any profile knows is accepted and checked again in JobFor.
	candidates := profile.All()
	if isExplicit {
		candidates = []profile.Profile{explicit}
	}
	known := func(kind string) bool {
		for _, p := range candidates {
			if _, ok := p.Kind(kind); ok {
				return true
			}
		}
		return false
	}
	for _, o := range c.Scope.Objects {
		if !known(o) {
			return fmt.Errorf("[scope] objects: unknown kind %q (available: %s)", o, strings.Join(candidates[0].KindNames(), ", "))
		}
	}
	for k := range c.Scope.Filters {
		if !known(k) {
			return fmt.Errorf("[scope.filters] unknown kind %q", k)
		}
	}
	// With profile = auto the attribute rules depend on the server, so they are checked in PlanOptionsFor.
	if isExplicit {
		return c.checkAttributes(explicit)
	}
	return nil
}

func (m Mapping) validate() error {
	switch m.Mode {
	case MappingAuto, MappingPreserve, MappingMarker, MappingFile, MappingOff:
	default:
		return fmt.Errorf("[mapping] mode must be auto, preserve, marker, file or off, got %q", m.Mode)
	}
	if m.File != "" && m.Mode != MappingFile {
		return fmt.Errorf("[mapping] file is used only with mode = %q", MappingFile)
	}
	if m.Attribute != "" && m.Mode != MappingAuto && m.Mode != MappingMarker {
		return fmt.Errorf("[mapping] attribute is used only with mode = %q", MappingMarker)
	}
	if m.OperationalText != nil && m.Mode != MappingAuto && m.Mode != MappingPreserve {
		return fmt.Errorf("[mapping] operational is used only with mode = %q", MappingPreserve)
	}
	return nil
}

// MappingFor resolves [mapping] for a profile: auto becomes marker when an attribute is configured, preserve where
// the profile can preserve identifiers over LDAP, marker where it has a default marker attribute, and off
// otherwise. attr is the marker attribute for marker.
func (c *Config) MappingFor(p profile.Profile) (mode, attr string, err error) {
	m := c.Mapping
	attr = m.Attribute
	if attr == "" {
		attr = p.Marker
	}
	mode = m.Mode
	if mode == MappingAuto {
		switch {
		case m.Attribute != "":
			mode = MappingMarker
		case p.Preserve != nil:
			mode = MappingPreserve
		case p.Marker != "":
			mode = MappingMarker
		default:
			mode = MappingOff
		}
	}
	switch mode {
	case MappingPreserve:
		if p.Preserve == nil {
			return "", "", fmt.Errorf("[mapping] mode = %q: the %s profile cannot give the target the source identifiers over LDAP; use %q or %q", MappingPreserve, p.Name, MappingMarker, MappingFile)
		}
		return mode, "", nil
	case MappingMarker:
		if attr == "" {
			return "", "", fmt.Errorf("[mapping] mode = %q needs an attribute with the %s profile, which has no default", MappingMarker, p.Name)
		}
		if err := c.checkMarker(p, attr); err != nil {
			return "", "", err
		}
		return mode, attr, nil
	}
	return mode, "", nil
}

// checkMarker refuses a marker attribute that the tool would also copy, compare or mask, or one the server manages.
func (c *Config) checkMarker(p profile.Profile, attr string) error {
	if profile.Set(p.NeverClone)[strings.ToLower(attr)] || strings.EqualFold(attr, p.Identity.Attr()) {
		return fmt.Errorf("[mapping] attribute %q is managed by the server or a credential and cannot hold a marker", attr)
	}
	for _, a := range c.Mask.Attributes {
		if strings.EqualFold(a, attr) {
			return fmt.Errorf("[mapping] attribute %q is masked; a masked attribute cannot hold a marker", attr)
		}
	}
	for _, kind := range c.objects(p) {
		list, err := p.Attrs(kind, c.override())
		if err != nil {
			continue // reported by checkAttributes
		}
		for _, a := range list {
			if strings.EqualFold(a, attr) {
				return fmt.Errorf("[mapping] attribute %q is in the attributes of %s, so clone would copy it and diff compare it; choose another or exclude it", attr, kind)
			}
		}
	}
	return nil
}

func (c *Config) checkAttributes(p profile.Profile) error {
	for _, a := range c.Mask.Attributes {
		if !p.Maskable(a) {
			return fmt.Errorf("[mask] attribute %q cannot be masked with a fixed string (identity, unique, DN-reference or non-string attribute)", a)
		}
	}
	for _, kind := range c.objects(p) {
		if _, err := p.Attrs(kind, c.override()); err != nil {
			return fmt.Errorf("[attributes] %s: %w", kind, err)
		}
	}
	return nil
}

// explicitProfile returns the profile named in the config. ok is false for auto (resolved against the server later).
func (c *Config) explicitProfile() (p profile.Profile, ok bool, err error) {
	if c.Scope.Profile == "" || strings.EqualFold(c.Scope.Profile, profile.NameAuto) {
		return profile.Profile{}, false, nil
	}
	p, err = profile.ByName(c.Scope.Profile)
	if err != nil {
		return p, false, fmt.Errorf("[scope] profile: %w", err)
	}
	return p, true, nil
}

// ProfileName is the profile name from the config (auto when not set).
func (c *Config) ProfileName() string {
	if c.Scope.Profile == "" {
		return profile.NameAuto
	}
	return c.Scope.Profile
}

// objects are the kinds [scope] objects enables for p: every kind of the profile when it is not set.
func (c *Config) objects(p profile.Profile) []string {
	if len(c.Scope.Objects) == 0 {
		return p.KindNames()
	}
	return c.Scope.Objects
}

func (c *Config) override() profile.Override {
	return profile.Override{Include: c.Attributes.Include, Extra: c.Attributes.Extra, Exclude: c.Attributes.Exclude}
}

// JobFor assembles what clone and diff work on, once the server type is known.
func (c *Config) JobFor(p profile.Profile) (plan.Job, error) {
	if err := c.checkAttributes(p); err != nil {
		return plan.Job{}, err
	}
	if _, _, err := c.MappingFor(p); err != nil {
		return plan.Job{}, err
	}
	job := plan.Job{Profile: p, RootDN: c.Scope.RootDN, BaseDN: c.Scope.BaseDN, Masker: mask.New(c.Mask.Value, c.Mask.Attributes),
		References: c.Scope.References}
	for _, spec := range p.Kinds { // the profile's order, whatever order the config lists them in
		if !contains(c.objects(p), spec.Name) {
			continue
		}
		list, err := p.Attrs(spec.Name, c.override())
		if err != nil {
			return plan.Job{}, fmt.Errorf("[attributes] %s: %w", spec.Name, err)
		}
		job.Kinds = append(job.Kinds, plan.NewKind(p, spec, c.Scope.Filters[spec.Name], list))
	}
	for _, o := range c.Scope.Objects {
		if _, ok := p.Kind(o); !ok {
			return plan.Job{}, fmt.Errorf("[scope] objects: the %s profile has no kind %q", p.Name, o)
		}
	}
	return job, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

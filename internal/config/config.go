// Package config loads and validates the TOML configuration. The bind passwords are never stored in the config file;
// the only password it may hold is the fixed one clone gives the cloned users, a value of the test environment.
package config

import (
	"bytes"
	"errors"
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
	// DefaultMaskValue is what a masked attribute gets unless [mask] value says otherwise.
	DefaultMaskValue = "********"
	defaultWorkers   = 8
	// DefaultTimeout is generous because a single modify of a large group on Samba can take seconds; its job is only
	// to turn a hung server into an error.
	DefaultTimeout = 2 * time.Minute
)

type Endpoint struct {
	// LDIF ([source] only) is a dump (ldap-cronin dump) read instead of a server: url, bind_dn and the rest are then
	// not given, and no password is asked.
	LDIF               string `toml:"ldif"`
	URL                string `toml:"url"`
	BindDN             string `toml:"bind_dn"`
	CAFile             string `toml:"ca_file"`
	InsecureSkipVerify bool   `toml:"insecure_skip_verify"`
	StartTLS           bool   `toml:"start_tls"`
	// TimeoutText bounds each LDAP operation ("30s", "2m"; "0" for no limit). Read it through Timeout.
	TimeoutText string `toml:"timeout"`
	timeout     time.Duration
	// Lab ([target] only) says the target is a lab of ldap-cronin lab, and how clone writes it.
	Lab *Lab `toml:"lab"`
}

// Lab is [target.lab]: which lab the target is, and whether clone writes its database directly.
type Lab struct {
	// Platform is where the lab runs: docker (the default: Samba4 or OpenLDAP in a container) or ec2 (a Windows
	// Server domain controller on Amazon EC2, made through the aws command).
	Platform string `toml:"platform"`
	// Prefix and Instance name the lab's container (<prefix>-ad, or <prefix>-ad-<instance>), as lab --prefix and
	// --instance do. lab up --config takes them from here.
	Prefix   string `toml:"prefix"`
	Instance string `toml:"instance"`
	// Native makes clone stop the lab and write Samba's database directly, keeping the source's objectGUID and
	// objectSid (Samba only; unsupported internals). url stays the lab's LDAP endpoint, which check, diff and
	// schema read, and which must be the lab's port.
	Native bool `toml:"native"`
	// Image is the lab image clone creates the lab from when it does not exist (default: the offline package's).
	Image string `toml:"image"`
	// FastPassword (native only) gives the users the fixed password's NT hash directly: about 3 times faster,
	// without Kerberos AES keys.
	FastPassword bool `toml:"fast_password"`
	// ServerAttributes (native only): "source" (the default) gives each object the source's values of what the
	// server keeps (whenCreated, lastLogonTimestamp, lastLogon, logonCount, lockoutTime, badPwdCount, sIDHistory,
	// mS-DS-CreatorSID); "lab" leaves the lab's own.
	ServerAttributes string `toml:"server_attributes"`
	// ACL (native only): "source" gives the lab's objects the source's owner, group and DACL, and the domain root and
	// the containers above base_dn theirs, so the inherited ACEs are the source's too; "lab" (the default) leaves the
	// lab's own. Off by default: few tests read ACLs, and the domain root's changes the whole lab.
	ACL string `toml:"acl"`

	// platform = "ec2": where and how the instance runs. The aws command's own configuration (credentials, profile)
	// applies; Region overrides its region.
	Region          string `toml:"region"`
	Subnet          string `toml:"subnet"`           // a subnet whose instances reach Systems Manager
	InstanceType    string `toml:"instance_type"`    // default t3.large
	Windows         string `toml:"windows"`          // Windows Server 2016, 2019, 2022 (default) or 2025
	InstanceProfile string `toml:"instance_profile"` // with AmazonSSMManagedInstanceCore
	// LDAPSName is one more DNS name of the lab's LDAPS certificate (its DC's and its domain's are always there).
	LDAPSName string `toml:"ldaps_name"`
	// LDAPPort (EC2) is the local port the instance's LDAP (389) is forwarded to too, for clients that do not use
	// LDAPS (clone itself does). The instance listens on 389 whatever it is.
	LDAPPort int `toml:"ldap_port"`
	// LDAPUnsigned (EC2) has the instance take a simple bind on 389 without signing, which Windows Server 2025
	// refuses by default for a new forest (2019 and 2022 take it).
	LDAPUnsigned bool `toml:"ldap_unsigned"`
	// RecycleBin (EC2) enables the AD Recycle Bin on the lab's forest.
	RecycleBin bool `toml:"recycle_bin"`
	// DiskSize (EC2) is the instance's root volume in GiB (default: the image's, 30).
	DiskSize int `toml:"disk_size"`
	// SecurityGroups (EC2) are attached to the instance (default: the VPC's default group).
	SecurityGroups []string `toml:"security_groups"`
	// Tags (EC2) are put on the instance and its volume, for an account whose policy requires some.
	Tags map[string]string `toml:"tags"`
	// PublicIP (EC2) gives the instance a public IPv4 address, for a subnet whose instances reach Systems Manager
	// through an internet gateway only. Without it the instance has none, whatever the subnet assigns.
	PublicIP bool `toml:"public_ip"`
}

// Platforms of [target.lab].
const (
	PlatformDocker = "docker"
	PlatformEC2    = "ec2"
)

// The [target.lab] server_attributes settings.
const (
	ServerAttributesSource = "source"
	ServerAttributesLab    = "lab"
)

// OnEC2 is whether the lab runs on Amazon EC2.
func (l *Lab) OnEC2() bool { return l != nil && l.Platform == PlatformEC2 }

// NativeLab is the target's [target.lab] when clone writes it directly, or nil.
func (c *Config) NativeLab() *Lab {
	if c.Target.Lab != nil && c.Target.Lab.Native {
		return c.Target.Lab
	}
	return nil
}

// Timeout is the parsed per-operation timeout.
func (e Endpoint) Timeout() time.Duration { return e.timeout }

// Scope is what clone and diff work on.
type Scope struct {
	// Profile is the server type: auto (default; asks the source's root DSE), ad or ldap.
	Profile string `toml:"profile"`
	// RootDN is the top of the naming context that holds base_dn. Only needed when it cannot be derived
	// (a generic LDAP base_dn without DC= components that the server does not list in namingContexts).
	RootDN string `toml:"root_dn"`
	// BaseDNValue is base_dn as written: a DN, or a list of DNs (several OUs as one scope). Read it through BaseDNs.
	BaseDNValue any `toml:"base_dn"`
	// BaseDNs is base_dn as a list, set by Parse.
	BaseDNs []string          `toml:"-"`
	Objects []string          `toml:"objects"` // empty: every kind of the profile
	Filters map[string]string `toml:"filters"`
	// References is what is done with a reference to an entry outside the scope: clone (default), existing or
	// skip (see plan.RefsClone).
	References string `toml:"references"`
	// ConfigurationRefs is what is done with a reference naming the configuration partition of AD (an Exchange
	// address list in showInAddressBook): skip (default) or clone (see plan.ConfigurationRefsClone).
	ConfigurationRefs string `toml:"configuration_refs"`
	// UnreadableRefs is what is done with a reference naming an entry of AD the source does not return (one the
	// reading account may not read): placeholder (default) or skip (see plan.UnreadableRefsPlaceholder).
	UnreadableRefs string `toml:"unreadable_refs"`
	// OutsideGroups is what is done with a group outside the scope that holds entries of it (a member): clone
	// (default), existing or skip (see plan.OutsideGroupsClone). BuiltinGroups is it for a built-in group (Domain
	// Admins): add (default) or skip.
	OutsideGroups string `toml:"outside_groups"`
	BuiltinGroups string `toml:"builtin_groups"`
}

// Run holds the run-time settings shared by clone and diff.
type Run struct {
	Workers int `toml:"workers"` // number of parallel target connections; 1 means sequential
}

// Accounts is how clone gives the cloned users and computers a password, as their hashes are never copied.
type Accounts struct {
	// FixedPassword is the password of every cloned user and computer. Empty: LDAP_CRONIN_USER_PASSWORD, or asked on
	// the terminal. It is a test value, never a bind password; a dry-run prints it only with -with-password.
	FixedPassword string `toml:"fixed_password"`
}

type Attributes struct {
	// Mode is AttributesListed (the default: the allow lists) or AttributesAll.
	Mode    string              `toml:"mode"`
	Include map[string][]string `toml:"include"`
	Extra   []string            `toml:"extra_include"`
	Exclude []string            `toml:"exclude"`
}

type Mask struct {
	Value      string   `toml:"value"`
	Attributes []string `toml:"attributes"` // masked on every entry
	// Kinds are attributes masked on the entries of a kind only ([mask.kinds] user = ["mail"]), besides Attributes.
	Kinds map[string][]string `toml:"kinds"`
}

// allMasked is every attribute [mask] names, on every entry or on a kind's.
func (m Mask) allMasked() []string {
	out := append([]string(nil), m.Attributes...)
	for _, attrs := range m.Kinds {
		out = append(out, attrs...)
	}
	return out
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
	Accounts   Accounts   `toml:"accounts"`
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
	bases, err := baseDNs(c.Scope.BaseDNValue)
	if err != nil {
		return nil, err
	}
	c.Scope.BaseDNs = bases
	if c.Run.Workers == 0 {
		c.Run.Workers = defaultWorkers
	}
	if c.Mask.Value == "" {
		c.Mask.Value = DefaultMaskValue
	}
	if c.Mapping.Mode == "" {
		c.Mapping.Mode = MappingAuto
	}
	if c.Mapping.Mode == MappingFile && c.Mapping.File == "" {
		c.Mapping.File = defaultMappingFile
	}
	for name, ep := range map[string]*Endpoint{"source": &c.Source, "target": &c.Target} {
		ep.timeout = DefaultTimeout
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

// The values of [attributes] mode.
const (
	// AttributesListed copies the attributes of the allow lists: the profile's defaults, include and extra_include.
	AttributesListed = "allowlist"
	// AttributesAll copies every attribute the source's schema lets a client write on the class of a kind, but
	// exclude and what clone never copies; the profile resolves it against the source (app.Open).
	AttributesAll = "all"
)

// All reports whether [attributes] mode is "all".
func (a Attributes) All() bool { return a.Mode == AttributesAll }

func (c *Config) validate() error {
	switch c.Attributes.Mode {
	case "", AttributesListed:
	case AttributesAll:
		if len(c.Attributes.Include) > 0 || len(c.Attributes.Extra) > 0 {
			return fmt.Errorf("[attributes] mode = %q copies every attribute a client can write; include and extra_include are for mode = %q (exclude still applies)", AttributesAll, AttributesListed)
		}
	default:
		return fmt.Errorf("[attributes] mode must be %q or %q, got %q", AttributesListed, AttributesAll, c.Attributes.Mode)
	}
	switch c.Scope.References {
	case "", plan.RefsClone, plan.RefsExisting, plan.RefsSkip:
	default:
		return fmt.Errorf("[scope] references must be %q, %q or %q, got %q", plan.RefsClone, plan.RefsExisting, plan.RefsSkip, c.Scope.References)
	}
	switch c.Scope.ConfigurationRefs {
	case "", plan.ConfigurationRefsSkip:
	case plan.ConfigurationRefsClone:
		if c.Scope.References != "" && c.Scope.References != plan.RefsClone {
			return fmt.Errorf("[scope] configuration_refs = %q creates what references name, so it needs references = %q", plan.ConfigurationRefsClone, plan.RefsClone)
		}
	default:
		return fmt.Errorf("[scope] configuration_refs must be %q or %q, got %q", plan.ConfigurationRefsSkip, plan.ConfigurationRefsClone, c.Scope.ConfigurationRefs)
	}
	switch c.Scope.UnreadableRefs {
	case "", plan.UnreadableRefsPlaceholder, plan.UnreadableRefsSkip:
	default:
		return fmt.Errorf("[scope] unreadable_refs must be %q or %q, got %q", plan.UnreadableRefsPlaceholder, plan.UnreadableRefsSkip, c.Scope.UnreadableRefs)
	}
	switch c.Scope.OutsideGroups {
	case "", plan.OutsideGroupsClone, plan.OutsideGroupsExisting, plan.OutsideGroupsSkip:
	default:
		return fmt.Errorf("[scope] outside_groups must be %q, %q or %q, got %q", plan.OutsideGroupsClone, plan.OutsideGroupsExisting, plan.OutsideGroupsSkip, c.Scope.OutsideGroups)
	}
	switch c.Scope.BuiltinGroups {
	case "", plan.BuiltinGroupsAdd, plan.BuiltinGroupsSkip:
	default:
		return fmt.Errorf("[scope] builtin_groups must be %q or %q, got %q", plan.BuiltinGroupsAdd, plan.BuiltinGroupsSkip, c.Scope.BuiltinGroups)
	}
	if c.Target.LDIF != "" {
		return errors.New("[target] ldif: a dump can only be a source")
	}
	if c.Source.Lab != nil {
		return errors.New("[source.lab]: a lab is a target ([target.lab])")
	}
	if l := c.Target.Lab; l != nil {
		ec2 := map[string]string{"region": l.Region, "subnet": l.Subnet, "instance_type": l.InstanceType, "windows": l.Windows,
			"instance_profile": l.InstanceProfile, "ldaps_name": l.LDAPSName}
		switch l.Platform {
		case "", PlatformDocker:
			for key, v := range ec2 {
				if v != "" {
					return fmt.Errorf("[target.lab] %s is for platform = %q", key, PlatformEC2)
				}
			}
			if l.LDAPPort != 0 {
				return fmt.Errorf("[target.lab] ldap_port is for platform = %q (a docker lab publishes LDAP on its own port)", PlatformEC2)
			}
			if l.LDAPUnsigned {
				return fmt.Errorf("[target.lab] ldap_unsigned is for platform = %q (Samba's LDAP is the lab's own)", PlatformEC2)
			}
			if l.RecycleBin {
				return fmt.Errorf("[target.lab] recycle_bin is for platform = %q (Samba has no AD Recycle Bin)", PlatformEC2)
			}
			if l.DiskSize != 0 || len(l.SecurityGroups) > 0 || len(l.Tags) > 0 || l.PublicIP {
				return fmt.Errorf("[target.lab] disk_size, security_groups, tags and public_ip are for platform = %q", PlatformEC2)
			}
		case PlatformEC2:
			if l.Native {
				return errors.New("[target.lab] native = true is for a Samba lab (platform = \"docker\"): Windows lets no one choose an objectGUID or a domain SID")
			}
			if l.Image != "" {
				return errors.New("[target.lab] image is a docker image: on EC2 the lab is Windows Server (windows = \"2022\")")
			}
			for _, key := range []string{"region", "subnet", "instance_profile"} {
				if ec2[key] == "" {
					return fmt.Errorf("[target.lab] platform = %q needs %s", PlatformEC2, key)
				}
			}
			switch l.Windows {
			case "", "2016", "2019", "2022", "2025":
			default:
				return fmt.Errorf("[target.lab] windows must be 2016, 2019, 2022 or 2025, got %q", l.Windows)
			}
		default:
			return fmt.Errorf("[target.lab] platform must be %q or %q, got %q", PlatformDocker, PlatformEC2, l.Platform)
		}
		if l.FastPassword && !l.Native {
			return errors.New("[target.lab] fast_password is for native = true: it writes the lab's database directly")
		}
		switch l.ServerAttributes {
		case "", ServerAttributesSource, ServerAttributesLab:
		default:
			return fmt.Errorf("[target.lab] server_attributes must be %q or %q, got %q", ServerAttributesSource, ServerAttributesLab, l.ServerAttributes)
		}
		switch l.ACL {
		case "", ServerAttributesSource, ServerAttributesLab:
		default:
			return fmt.Errorf("[target.lab] acl must be %q or %q, got %q", ServerAttributesSource, ServerAttributesLab, l.ACL)
		}
		if l.ACL != "" && !l.Native {
			return errors.New("[target.lab] acl is for native = true (copying ACLs over LDAP is not there yet)")
		}
		if l.ServerAttributes != "" && !l.Native {
			return errors.New("[target.lab] server_attributes is for native = true: over LDAP only the server sets them")
		}
		if l.Native && c.Scope.ConfigurationRefs == plan.ConfigurationRefsClone {
			return fmt.Errorf("[target.lab] native = true writes the domain partition only; [scope] configuration_refs = %q needs a clone over LDAP", plan.ConfigurationRefsClone)
		}
	}
	if c.Source.LDIF != "" && (c.Source.URL != "" || c.Source.BindDN != "" || c.Source.CAFile != "" || c.Source.StartTLS || c.Source.InsecureSkipVerify) {
		return errors.New("[source] ldif reads a dump instead of a server: leave out url, bind_dn and the connection settings")
	}
	for name, ep := range map[string]Endpoint{"source": c.Source, "target": c.Target} {
		if ep.LDIF != "" {
			continue
		}
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
	if c.Source.LDIF == "" && strings.EqualFold(strings.TrimRight(c.Source.URL, "/"), strings.TrimRight(c.Target.URL, "/")) {
		return fmt.Errorf("source and target are the same server (%s)", c.Source.URL)
	}
	if err := plan.CheckBases(c.Scope.BaseDNs); err != nil {
		return fmt.Errorf("[scope] %w", err)
	}
	explicit, isExplicit, err := c.explicitProfile()
	if err != nil {
		return err
	}
	// Where the naming context starts is the profile's business and may need the server, so only reject what is
	// certainly wrong here: a base_dn outside the root it was given. The root itself is the whole naming context.
	for _, b := range c.Scope.BaseDNs {
		if root := c.Scope.RootDN; root != "" && !dn.Equal(b, root) && !dn.IsDescendant(b, root) {
			return fmt.Errorf("[scope] base_dn must be the root (root_dn) or below it: %q", b)
		}
		if root := dn.DomainRoot(c.Scope.BaseDNs[0]); c.Scope.RootDN == "" && root != "" && !dn.Equal(dn.DomainRoot(b), root) {
			return fmt.Errorf("[scope] every base_dn must be in one domain: %q is not in %q", b, root)
		}
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
	for _, a := range c.Mask.allMasked() {
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
	for _, a := range c.Mask.allMasked() {
		if !p.Maskable(a) {
			return fmt.Errorf("[mask] attribute %q cannot be masked with a fixed string (identity, unique, DN-reference or non-string attribute)", a)
		}
	}
	for kind := range c.Mask.Kinds {
		if _, ok := p.Kind(kind); !ok {
			return fmt.Errorf("[mask.kinds] unknown kind %q (available: %s)", kind, strings.Join(p.KindNames(), ", "))
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
	job := plan.Job{Profile: p, RootDN: c.Scope.RootDN, BaseDNs: c.Scope.BaseDNs, Masker: mask.New(c.Mask.Value, c.Mask.Attributes).WithKinds(c.Mask.Kinds),
		References: c.Scope.References, ConfigurationRefs: c.Scope.ConfigurationRefs, UnreadableRefs: c.Scope.UnreadableRefs,
		OutsideGroups: c.Scope.OutsideGroups, BuiltinGroups: c.Scope.BuiltinGroups,
		ACL: c.Target.Lab != nil && c.Target.Lab.Native && c.Target.Lab.ACL == ServerAttributesSource}
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

// baseDNs reads base_dn: a DN, or a list of DNs.
func baseDNs(v any) ([]string, error) {
	switch v := v.(type) {
	case nil:
		return nil, nil
	case string:
		if v == "" {
			return nil, nil
		}
		return []string{v}, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			s, ok := x.(string)
			if !ok || s == "" {
				return nil, fmt.Errorf("parse config: [scope] base_dn: every value of the list must be a DN, got %v", x)
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, fmt.Errorf("parse config: [scope] base_dn must be a DN or a list of DNs, got %T", v)
}

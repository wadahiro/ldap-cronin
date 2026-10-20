// Package profile collects everything that differs between Active Directory (and Samba AD) and a plain LDAP server.
//
// Lists are data: the kinds with their default filters and attribute lists, the never-clone and never-mask lists.
// They are what a deployment tweaks through the config file and what list-attrs prints. Behavior is a strategy:
// how DN-valued attributes are found, where the naming context starts, how an account gets its password, how values
// compare, how objects are identified. Shared code calls these instead of branching on a server name, so a third
// server type is a third value of Profile and nothing else.
//
// A profile per product (OpenLDAP, 389-ds, ...) was rejected: the RFC-level behavior is the same, and what differs
// per deployment (object classes, attributes) is covered by the per-kind filters and attribute lists in the config file.
package profile

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/compare"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/identity"
)

// Names of the profiles. Auto is only valid in the config file; it is resolved against the source's root DSE.
const (
	NameAD   = "ad"
	NameLDAP = "ldap"
	NameAuto = "auto"
)

// Names of the default kinds, the labels the config file uses ([scope] objects, [scope.filters], [attributes.include]).
const (
	KindOU       = "ou"
	KindGroup    = "group"
	KindUser     = "user"
	KindComputer = "computer"
	KindContact  = "contact"
)

// Role is what the tool does with entries of a kind. Only the role matters to the shared code, never the kind name.
type Role int

const (
	// RoleContainer entries are created shallowest first, because children need them, and are held in memory.
	RoleContainer Role = iota
	// RoleLeaf entries are streamed: they do not depend on each other (references are applied afterwards).
	RoleLeaf
)

// KindSpec is one kind of object the tool selects.
type KindSpec struct {
	Name   string
	Role   Role
	Filter string
	// Default is the default attribute allow list (without the profile's Required attributes).
	Default []string
	// Order is the creation order among leaves.
	Order int
	// Account marks kinds whose entries are accounts: they are created through the profile's Account strategy.
	Account bool
	// Is tells, from an entry's object classes, whether it is of this kind, as Filter would without its
	// configured narrowing. It classifies an entry outside the scope that a reference names.
	Is func(objectClasses []string) bool
}

// hasClass reports whether classes holds every name of want and none of not (case-insensitively).
func hasClass(classes []string, want []string, not ...string) bool {
	has := func(n string) bool {
		for _, c := range classes {
			if strings.EqualFold(c, n) {
				return true
			}
		}
		return false
	}
	for _, w := range want {
		if !has(w) {
			return false
		}
	}
	for _, n := range not {
		if has(n) {
			return false
		}
	}
	return true
}

func classIs(want ...string) func([]string) bool {
	return func(c []string) bool { return hasClass(c, want) }
}

func classIsAny(any ...string) func([]string) bool {
	return func(c []string) bool {
		for _, a := range any {
			if hasClass(c, []string{a}) {
				return true
			}
		}
		return false
	}
}

// RefInfo describes an attribute whose values are DNs.
type RefInfo struct{ Single bool }

// Schema is what the source schema says about DN-valued attributes.
type Schema struct {
	Refs map[string]RefInfo // lowercase name
	// BackLinks are computed by the server (memberOf, directReports, ...) and cannot be written.
	BackLinks map[string]bool
	// Unsupported hold a DN inside a larger value (DN-Binary, DN-String) that this tool cannot rewrite.
	Unsupported map[string]bool
}

// RefDiscoverer finds the DN-valued attributes in the source schema. A fixed list would break attributes added
// through extra_include (seeAlso, Exchange publicDelegates, ...): they would fail depending on the creation order of
// their targets, or show false differences in diff.
type RefDiscoverer interface {
	// Discover returns ok=false when the schema cannot be read (test directories without a root DSE); the
	// profile's BuiltinRefs are then used alone.
	Discover(ctx context.Context, src directory.Directory) (s Schema, ok bool, err error)
}

// AttributeLister reads the names of the attributes a schema defines.
type AttributeLister interface {
	// Attributes returns the lowercase names; ok=false when the schema cannot be read (test directories, the
	// dry-run), and the check that uses it is then skipped.
	Attributes(ctx context.Context, d directory.Directory) (names map[string]bool, ok bool, err error)
}

// SchemaCopier plans what a target's schema lacks of the source's extensions (the attributes and classes an
// organization or a product added), so a lab can be given them before the first clone.
type SchemaCopier interface {
	// PlanSchema returns ok=false when either schema cannot be read.
	PlanSchema(ctx context.Context, src, dst directory.Directory) (plan SchemaChanges, ok bool, err error)
}

// SchemaChanges is a plan of schema changes: written to the target, or printed for an administrator to apply.
type SchemaChanges interface {
	Empty() bool
	WriteSummary(w io.Writer)
	WriteLDIF(w io.Writer) error
	Apply(ctx context.Context, dst directory.Directory, log io.Writer) error
}

// RootResolver finds the top of the naming context that holds base_dn. [scope] root_dn, when set, bypasses it.
type RootResolver interface {
	Root(ctx context.Context, src directory.Directory, baseDN string) (string, error)
}

// NativeSupport reads what a lab needs to be provisioned as the same domain as the source (clone -native).
type NativeSupport interface {
	Domain(ctx context.Context, src directory.Directory, root string) (Domain, error)
}

// Preserver keeps the source identifier when an object is created over LDAP: the Add carries the identifier and a
// control that lets a client set it. The target object's own identifier is then the source key, and diff needs
// neither a marker nor a mapping file.
type Preserver struct {
	Control directory.Control
	// Operational are the other server-maintained attributes the control lets an Add set. They are copied at
	// creation when [mapping] operational is on (the default), so the target looks like production, and are never
	// compared: any later change on the target updates modifyTimestamp.
	Operational []string
	// Remedy is said when the target refuses the control.
	Remedy string
}

// MarkerChecker validates the attribute that holds the marker against the target schema before anything is written.
type MarkerChecker interface {
	// CheckMarker returns an error when attr cannot hold a marker of minLen characters, and a warning when it can
	// but every lookup by marker will be slow (no index).
	CheckMarker(ctx context.Context, dst directory.Directory, attr string, minLen int) (warning string, err error)
}

// Domain identifies a source domain for a native import.
type Domain struct{ Root, Realm, NetBIOS, SID, GUID string }

type Profile struct {
	Name  string
	Kinds []KindSpec
	// Required attributes are always read and written and cannot be removed by configuration.
	Required []string
	// AncestorAttrs are read and written for a create-only ancestor (a parent above or between the selected
	// entries). Borrowing the OU allow list was rejected: an ancestor that is not an OU may need an attribute that
	// list does not have.
	AncestorAttrs []string
	// NeverClone attributes are server-managed or credentials; adding them to the allow list is an error.
	NeverClone []string
	// NoMask attributes would break the tool or violate a constraint if replaced by a fixed string.
	NoMask []string
	// PasswordAttrs are the credentials (passwords, and on AD the computers' LAPS passwords, shadow credentials and
	// delegation): never copied, never compared and never printed. diff's summary names them.
	PasswordAttrs []string
	// SystemFilter excludes built-in objects (AD: isCriticalSystemObject). Empty means no exclusion.
	SystemFilter string
	// SystemAttr is the attribute whose value TRUE marks a built-in object, as SystemFilter does (empty: none).
	SystemAttr string
	// Principal returns how to write a reference to a principal every domain has (AD: a well-known foreign
	// security principal, written as <SID=...> so the target's DC creates it). nil: none.
	Principal func(dn string) (value string, ok bool)
	// BuiltinRefs are DN-valued attributes known without reading the schema (lowercase name).
	BuiltinRefs map[string]RefInfo
	// Ranged attributes are always fetched with the AD range option (member;range=0-N).
	Ranged []string
	// RefsAtCreation is true when a class may require a DN reference at creation (groupOfNames needs a member), so
	// an object class violation of an Add without the references is retried with them. Where none does (AD), the
	// violation is about something else (an attribute or class the target lacks) and is reported as it is.
	RefsAtCreation bool
	// RefsNeedEntry is true when the server accepts a DN reference only to an existing entry (AD's linked
	// attributes). A generic server takes any DN, so a value naming nothing cloned is still written as it is.
	RefsNeedEntry bool
	// Values holds per-attribute value normalizers (lowercase name) beyond the generic rules.
	Values map[string]compare.Normalizer

	Identity identity.Scheme
	// Preserve is nil when the target cannot be given the source identifiers over LDAP.
	Preserve *Preserver
	// Marker is the default attribute for the marker ([mapping] attribute); empty when the profile has none.
	Marker string
	// MarkerCheck is nil when the profile cannot read what the target schema says about an attribute.
	MarkerCheck MarkerChecker
	Refs        RefDiscoverer
	// SchemaAttrs lists the attributes of a schema, so clone can refuse to start when the target lacks one the
	// allow lists name and the source has. nil: no check.
	SchemaAttrs AttributeLister
	// SchemaCopy is nil when the profile cannot carry schema definitions (ldap-cronin schema).
	SchemaCopy SchemaCopier
	Root       RootResolver
	Account    Account
	// Native is nil when clone -native is not possible for this server type.
	Native NativeSupport
}

// Kind returns the spec of a kind by name.
func (p Profile) Kind(name string) (KindSpec, bool) {
	for _, k := range p.Kinds {
		if k.Name == name {
			return k, true
		}
	}
	return KindSpec{}, false
}

// KindNames lists the kinds in the order they are listed and reported.
func (p Profile) KindNames() []string {
	out := make([]string, 0, len(p.Kinds))
	for _, k := range p.Kinds {
		out = append(out, k.Name)
	}
	return out
}

// Override is an allow-list adjustment that comes from the config file.
type Override struct {
	Include map[string][]string // replaces the defaults per kind
	Extra   []string            // added to the defaults of all kinds
	Exclude []string            // removed from all kinds
}

// Attrs returns the final attribute allow list of a kind: the required attributes, the defaults (or their
// replacement) and the extra ones, without the excluded ones.
//
// The tool is allow-list based rather than exclude-list based, because with an exclude list unexpected attributes
// such as extensionAttribute* would silently land in the target.
func (p Profile) Attrs(kind string, o Override) ([]string, error) {
	spec, ok := p.Kind(kind)
	if !ok {
		return nil, fmt.Errorf("unknown object kind %q", kind)
	}
	base := spec.Default
	if inc, ok := o.Include[kind]; ok {
		base = inc
	}
	never, excluded, required := Set(p.NeverClone), Set(o.Exclude), Set(p.Required)
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{p.Required, base, o.Extra} {
		for _, name := range list {
			key := strings.ToLower(name)
			if never[key] {
				return nil, fmt.Errorf("attribute %q cannot be cloned", name)
			}
			if seen[key] || (excluded[key] && !required[key]) {
				continue
			}
			seen[key] = true
			out = append(out, name)
		}
	}
	return out, nil
}

// Maskable reports whether name can be replaced by a fixed string.
func (p Profile) Maskable(name string) bool { return !Set(p.NoMask)[strings.ToLower(name)] }

// ByName returns the profile for an explicit name (ad or ldap).
func ByName(name string) (Profile, error) {
	for _, p := range All() {
		if strings.EqualFold(p.Name, name) {
			return p, nil
		}
	}
	return Profile{}, fmt.Errorf("unknown profile %q (available: %s, %s, %s)", name, NameAuto, NameAD, NameLDAP)
}

// All lists every profile, for validating the config before the server type is known.
func All() []Profile { return []Profile{AD, LDAP} }

// adCapability is LDAP_CAP_ACTIVE_DIRECTORY_OID in supportedCapabilities. Samba AD advertises it too.
const adCapability = "1.2.840.113556.1.4.800"

// Detect decides between AD and plain LDAP from the root DSE.
func Detect(ctx context.Context, d directory.Directory) (Profile, error) {
	root, err := d.Get(ctx, "", []string{"supportedCapabilities"})
	if err != nil {
		return Profile{}, fmt.Errorf("read root DSE to detect the server type: %w", err)
	}
	if root != nil {
		for _, v := range root.Values("supportedCapabilities") {
			if v == adCapability {
				return AD, nil
			}
		}
	}
	return LDAP, nil
}

// Resolve returns the named profile; for auto it asks the server.
func Resolve(ctx context.Context, name string, d directory.Directory) (Profile, error) {
	if name == "" || strings.EqualFold(name, NameAuto) {
		return Detect(ctx, d)
	}
	return ByName(name)
}

// Set is a case-insensitive set of attribute names.
func Set(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[strings.ToLower(n)] = true
	}
	return out
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

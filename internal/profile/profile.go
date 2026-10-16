// Package profile collects everything that differs between Active Directory (and Samba AD) and a plain LDAP server:
// default filters and attribute lists, the identifier attribute, password handling and schema discovery.
//
// A profile is data, not a code path per server product. A product-specific profile (OpenLDAP, 389-ds, ...) was rejected:
// the RFC-level behavior is the same, and what differs per deployment (object classes, attributes) is covered by the
// per-kind filters and attribute lists in the config file.
package profile

import (
	"fmt"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// Names of the profiles. Auto is only valid in the config file; it is resolved against the source's root DSE.
const (
	NameAD   = "ad"
	NameLDAP = "ldap"
	NameAuto = "auto"
)

// Object kinds.
const (
	KindOU    = "ou"
	KindGroup = "group"
	KindUser  = "user"
)

// PasswordMode says how a user's fixed password is set on the target.
type PasswordMode int

const (
	// PasswordUnicodePwd sets unicodePwd (quoted UTF-16LE) with a modify over LDAPS, then userAccountControl.
	PasswordUnicodePwd PasswordMode = iota
	// PasswordUserPassword replaces userPassword with the plain password (the server hashes it).
	PasswordUserPassword
)

// SchemaMode says how attributes that hold DNs are discovered.
type SchemaMode int

const (
	// SchemaAD reads attributeSchema entries (attributeSyntax 2.5.5.1) from the schema naming context.
	SchemaAD SchemaMode = iota
	// SchemaSubschema reads attributeTypes from the subschema subentry (RFC 4512) and follows SUP.
	SchemaSubschema
)

type Profile struct {
	Name string
	// Filters are the default search filters per kind.
	Filters map[string]string
	// Defaults are the default attribute allow lists per kind (without the required attributes).
	Defaults map[string][]string
	// Required attributes are always read and written and cannot be removed by configuration.
	Required []string
	// NeverClone attributes are server-managed or credentials; adding them to the allow list is an error.
	NeverClone []string
	// NoMask attributes would break the tool or violate a constraint if replaced by a fixed string.
	NoMask []string
	// SystemFilter excludes built-in objects (AD: isCriticalSystemObject). Empty means no exclusion.
	SystemFilter string
	// IDAttr is the attribute that identifies an object across renames and moves.
	IDAttr string
	// IDIsText is true when the identifier is returned (and searched) as text, as entryUUID is, not as raw bytes.
	IDIsText bool
	// BuiltinRefs are DN-valued attributes known without reading the schema (name, lowercase -> single-valued).
	BuiltinRefs map[string]bool
	Schema      SchemaMode
	// RangedAttrs are retrieved with the AD range option (member;range=0-N).
	RangedAttrs []string
	// PasswordAttrs are never copied and never compared.
	PasswordAttrs []string
	Password      PasswordMode
	// LeafOrder is the order in which groups and users are created.
	LeafOrder []string
	// SupportsNative is true when objectGUID/objectSid import into a lab Samba is possible.
	SupportsNative bool
}

// AD is Active Directory and Samba AD.
var AD = Profile{
	Name: NameAD,
	Filters: map[string]string{
		KindOU:    "(objectClass=organizationalUnit)",
		KindGroup: "(objectClass=group)",
		KindUser:  "(&(objectCategory=person)(objectClass=user))",
	},
	Defaults: map[string][]string{
		KindOU: {
			"description", "displayName", "street", "l", "st", "postalCode", "co", "c", "managedBy",
		},
		KindGroup: {
			"sAMAccountName", "groupType", "description", "displayName", "info", "mail",
			"managedBy", "member", "adminDescription", "gidNumber",
		},
		KindUser: {
			"sAMAccountName", "userPrincipalName", "userAccountControl", "accountExpires",
			"givenName", "sn", "initials", "middleName", "displayName", "description",
			"mail", "telephoneNumber", "mobile", "homePhone", "pager", "ipPhone",
			"facsimileTelephoneNumber", "title", "department", "company", "division",
			"physicalDeliveryOfficeName", "manager", "employeeID", "employeeNumber", "employeeType",
			"streetAddress", "postOfficeBox", "l", "st", "postalCode", "co", "c",
			"wWWHomePage", "url", "info", "homeDirectory", "homeDrive", "scriptPath", "profilePath",
			"uidNumber", "gidNumber", "loginShell", "unixHomeDirectory",
		},
	},
	Required: []string{"objectClass", "cn", "ou"},
	NeverClone: []string{
		"objectGUID", "objectSid", "sIDHistory", "whenCreated", "whenChanged", "uSNCreated", "uSNChanged",
		"distinguishedName", "name", "pwdLastSet", "badPwdCount", "badPasswordTime", "lastLogon",
		"lastLogoff", "lastLogonTimestamp", "logonCount", "lockoutTime", "memberOf", "unicodePwd",
		"dBCSPwd", "ntPwdHistory", "lmPwdHistory", "supplementalCredentials", "sAMAccountType",
		"objectCategory", "instanceType", "nTSecurityDescriptor", "isCriticalSystemObject",
		"systemFlags", "dSCorePropagationData", "primaryGroupID", "msDS-KeyVersionNumber",
	},
	NoMask: []string{
		"objectClass", "cn", "ou", "sAMAccountName", "userPrincipalName", "servicePrincipalName",
		"member", "manager", "managedBy", "userAccountControl", "groupType", "accountExpires",
		"countryCode", "c", "uidNumber", "gidNumber",
	},
	SystemFilter:   "(!(isCriticalSystemObject=TRUE))",
	IDAttr:         "objectGUID",
	BuiltinRefs:    map[string]bool{"member": false, "manager": true, "managedby": true},
	Schema:         SchemaAD,
	RangedAttrs:    []string{"member"},
	PasswordAttrs:  []string{"unicodePwd", "dBCSPwd", "ntPwdHistory", "lmPwdHistory", "supplementalCredentials"},
	Password:       PasswordUnicodePwd,
	LeafOrder:      []string{KindGroup, KindUser},
	SupportsNative: true,
}

// LDAP is a generic RFC 4510 server (OpenLDAP, 389 Directory Server, ...): inetOrgPerson users, groupOfNames groups.
var LDAP = Profile{
	Name: NameLDAP,
	Filters: map[string]string{
		KindOU:    "(objectClass=organizationalUnit)",
		KindGroup: "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))",
		KindUser:  "(objectClass=inetOrgPerson)",
	},
	Defaults: map[string][]string{
		KindOU: {
			"description", "businessCategory", "street", "l", "st", "postalCode", "postalAddress",
			"telephoneNumber", "facsimileTelephoneNumber", "seeAlso",
		},
		KindGroup: {
			"description", "member", "uniqueMember", "owner", "seeAlso", "businessCategory",
			"gidNumber", "memberUid",
		},
		KindUser: {
			"uid", "givenName", "sn", "displayName", "description", "initials", "mail",
			"telephoneNumber", "mobile", "homePhone", "pager", "facsimileTelephoneNumber",
			"title", "departmentNumber", "employeeNumber", "employeeType", "o", "ou",
			"street", "l", "st", "postalCode", "postalAddress", "postOfficeBox",
			"physicalDeliveryOfficeName", "manager", "secretary", "preferredLanguage", "labeledURI",
			"uidNumber", "gidNumber", "homeDirectory", "loginShell", "gecos",
		},
	},
	// dc and o are needed to create the naming-context-level ancestors that are not OUs.
	Required: []string{"objectClass", "cn", "ou", "dc", "o"},
	NeverClone: []string{
		"entryUUID", "entryCSN", "entryDN", "createTimestamp", "modifyTimestamp", "creatorsName", "modifiersName",
		"structuralObjectClass", "hasSubordinates", "subschemaSubentry", "memberOf", "pwdChangedTime",
		"pwdFailureTime", "pwdAccountLockedTime", "pwdHistory", "pwdReset", "userPassword", "authPassword",
		"sambaNTPassword", "sambaLMPassword", "nsUniqueId", "modifyTimestamp",
	},
	NoMask: []string{
		"objectClass", "cn", "ou", "uid", "dc", "o", "member", "uniqueMember", "owner", "manager", "secretary",
		"seeAlso", "roleOccupant", "memberUid", "uidNumber", "gidNumber", "c",
	},
	IDAttr:   "entryUUID",
	IDIsText: true,
	BuiltinRefs: map[string]bool{
		"member": false, "uniquemember": false, "owner": false, "seealso": false, "manager": false,
		"secretary": false, "roleoccupant": false,
	},
	Schema:        SchemaSubschema,
	PasswordAttrs: []string{"userPassword", "authPassword", "sambaNTPassword", "sambaLMPassword", "pwdHistory"},
	Password:      PasswordUserPassword,
	LeafOrder:     []string{KindUser, KindGroup},
}

// ByName returns the profile for an explicit name (ad or ldap).
func ByName(name string) (Profile, error) {
	switch strings.ToLower(name) {
	case NameAD:
		return AD, nil
	case NameLDAP:
		return LDAP, nil
	}
	return Profile{}, fmt.Errorf("unknown profile %q (available: %s, %s, %s)", name, NameAuto, NameAD, NameLDAP)
}

// adCapability is LDAP_CAP_ACTIVE_DIRECTORY_OID in supportedCapabilities. Samba AD advertises it too.
const adCapability = "1.2.840.113556.1.4.800"

// Detect decides between AD and plain LDAP from the root DSE.
func Detect(d directory.Directory) (Profile, error) {
	root, err := d.Get("", []string{"supportedCapabilities"})
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
func Resolve(name string, d directory.Directory) (Profile, error) {
	if name == "" || strings.EqualFold(name, NameAuto) {
		return Detect(d)
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

// Kinds is the order in which kinds are listed and processed structurally.
var Kinds = []string{KindOU, KindGroup, KindUser}

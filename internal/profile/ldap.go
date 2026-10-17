package profile

import (
	"context"
	"fmt"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/identity"
)

// LDAP is a generic RFC 4510 server (OpenLDAP, 389 Directory Server, ...): inetOrgPerson users, groupOfNames groups.
var LDAP = Profile{
	Name: NameLDAP,
	Kinds: []KindSpec{
		{Name: KindOU, Role: RoleContainer, Filter: "(objectClass=organizationalUnit)", Default: []string{
			"description", "businessCategory", "street", "l", "st", "postalCode", "postalAddress",
			"telephoneNumber", "facsimileTelephoneNumber", "seeAlso",
		}},
		{Name: KindGroup, Role: RoleLeaf, Order: 1, Filter: "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))", Default: []string{
			"description", "member", "uniqueMember", "owner", "seeAlso", "businessCategory",
			"gidNumber", "memberUid",
		}},
		// Users first: groupOfNames must have a member at creation (see clone), and its members are the users.
		{Name: KindUser, Role: RoleLeaf, Order: 0, Account: true, Filter: "(objectClass=inetOrgPerson)", Default: []string{
			"uid", "givenName", "sn", "displayName", "description", "initials", "mail",
			"telephoneNumber", "mobile", "homePhone", "pager", "facsimileTelephoneNumber",
			"title", "departmentNumber", "employeeNumber", "employeeType", "o", "ou",
			"street", "l", "st", "postalCode", "postalAddress", "postOfficeBox",
			"physicalDeliveryOfficeName", "manager", "secretary", "preferredLanguage", "labeledURI",
			"uidNumber", "gidNumber", "homeDirectory", "loginShell", "gecos",
		}},
	},
	Required: []string{"objectClass", "cn", "ou"},
	// dc and o name the naming-context-level ancestors that are not OUs (dc=example, o=acme).
	AncestorAttrs: []string{"objectClass", "cn", "ou", "dc", "o", "description"},
	NeverClone: []string{
		"entryUUID", "entryCSN", "entryDN", "createTimestamp", "modifyTimestamp", "creatorsName", "modifiersName",
		"structuralObjectClass", "hasSubordinates", "subschemaSubentry", "memberOf", "pwdChangedTime",
		"pwdFailureTime", "pwdAccountLockedTime", "pwdHistory", "pwdReset", "userPassword", "authPassword",
		"sambaNTPassword", "sambaLMPassword", "nsUniqueId",
	},
	NoMask: []string{
		"objectClass", "cn", "ou", "uid", "dc", "o", "member", "uniqueMember", "owner", "manager", "secretary",
		"seeAlso", "roleOccupant", "memberUid", "uidNumber", "gidNumber", "c",
	},
	PasswordAttrs: []string{"userPassword", "authPassword", "sambaNTPassword", "sambaLMPassword", "pwdHistory"},
	BuiltinRefs: map[string]RefInfo{
		"member": {}, "uniquemember": {}, "owner": {}, "seealso": {}, "manager": {}, "secretary": {}, "roleoccupant": {},
	},
	// No Ranged: OpenLDAP does not implement the range option and would return member empty.
	Identity: identity.EntryUUID,
	// The relax control (an expired Internet-Draft that OpenLDAP implements) lets an Add set entryUUID and the
	// creation and modification metadata. It is not advertised in the root DSE, so support shows on the first Add.
	// entryCSN cannot be set even with it.
	Preserve: &Preserver{
		Control:     directory.Control{OID: RelaxOID, Critical: true},
		Operational: []string{"createTimestamp", "modifyTimestamp", "creatorsName", "modifiersName"},
		Remedy: "the relax control needs manage access to the entries (or the rootdn) on OpenLDAP; " +
			"grant it, or set [mapping] mode = \"marker\" with an attribute, \"file\" or \"off\"",
	},
	Refs:    subschema{},
	Root:    namingContextRoot{},
	Account: ldapAccount{},
}

// RelaxOID is the relax control (draft-zeilenga-ldap-relax).
const RelaxOID = "1.3.6.1.4.1.4203.666.5.12"

// namingContextRoot is the longest namingContexts value above base_dn, falling back to the trailing DC= run; a
// base_dn without either needs [scope] root_dn.
type namingContextRoot struct{}

func (namingContextRoot) Root(ctx context.Context, src directory.Directory, baseDN string) (string, error) {
	rootDSE, err := src.Get(ctx, "", []string{"namingContexts"})
	if err != nil {
		return "", fmt.Errorf("read root DSE: %w", err)
	}
	best := ""
	if rootDSE != nil {
		for _, nc := range rootDSE.Values("namingContexts") {
			if dn.IsDescendant(baseDN, nc) && dn.Depth(nc) > dn.Depth(best) {
				best = nc
			}
		}
	}
	if best == "" {
		best = dn.DomainRoot(baseDN)
	}
	if best == "" {
		return "", fmt.Errorf("cannot determine the naming context of base_dn %q: set [scope] root_dn", baseDN)
	}
	return best, nil
}

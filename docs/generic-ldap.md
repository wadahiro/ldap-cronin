# Generic LDAP servers (OpenLDAP, 389 Directory Server, ...)

ldap-cronin clones and compares any RFC 4510 directory, not only Active Directory. Two **profiles** hold the differences:

| | `ad` (Active Directory, Samba AD) | `ldap` (generic) |
|---|---|---|
| Detection | root DSE `supportedCapabilities` contains `1.2.840.113556.1.4.800` | everything else |
| Users | `(&(objectCategory=person)(objectClass=user))` | `(objectClass=inetOrgPerson)` |
| Groups | `(objectClass=group)` | `groupOfNames`, `groupOfUniqueNames` or `posixGroup` |
| OUs | `organizationalUnit` | `organizationalUnit` |
| System objects | excluded (`isCriticalSystemObject=TRUE`) | none (there is no such marker) |
| Fixed password | add (disabled), `unicodePwd` modify over LDAPS, then `userAccountControl` | `userPassword` sent with the plain value in the add (the server hashes it) |
| DN-valued attributes | schema `attributeSyntax=2.5.5.1` | subschema `attributeTypes`, syntax DN / Name and Optional UID, following `SUP` |
| Object identity (renames) | `objectGUID` | `entryUUID` |
| Large `member` values | `member;range=0-N` | plain read |
| `clone -native`, `lab` | yes (Samba lab) | no |

The profile is `auto` by default. Set `[scope] profile = "ldap"` (or `"ad"`) to override the detection. With `auto` the target is checked too, and a source and target of different types are refused.
`ldap-cronin list-attrs -profile ldap` prints the default attributes.

## Configuration

```toml
[source]
url = "ldap://src.example.org:389"
bind_dn = "cn=admin,dc=example,dc=org"
[target]
url = "ldap://dst.example.org:389"
bind_dn = "cn=admin,dc=example,dc=org"
[scope]
base_dn = "ou=IDM,dc=example,dc=org"
# root_dn = "o=acme"       # only when it cannot be derived (see below)
[mapping]
file = "mapping"       # records entryUUID pairs so that diff can detect renames and moves
```

The **root** is the top of the naming context that holds `base_dn`. It must exist on the target and is never created or changed. It is taken from `root_dn`, otherwise from the longest `namingContexts` value above `base_dn`, otherwise from the trailing `dc=` components of `base_dn`.

## How it behaves

- **Groups that require a member.** `groupOfNames` must have at least one `member` when it is created. The tool first tries to create every entry without its DN references (they are applied afterwards, so creation order does not matter); if the server answers with an object class violation it retries with the references that point into the cloned scope. Users are therefore created before groups.
- **Passwords.** The source's password hashes are never copied (`userPassword` is on the never-clone list). Cloned users get the fixed password you enter, sent as `userPassword` in the add that creates them, so the target must accept it under its password policy. A user is never created without it, and a re-run never touches the password of a user that already exists (the program under test may have changed it). Whether the server stores the plain value or a hash is the server's setting, as for a modify (389-ds hashes it; OpenLDAP does with `ppolicy_hash_cleartext`).
- **References outside the cloned scope** are skipped with a warning, as for AD, unless the referenced entry already exists on the target.
- **Comparison.** Values are compared exactly, except DN-valued attributes (case and escaping are normalized) and `objectClass` (case-insensitive). Case-insensitive attributes such as `mail` or `cn` that differ only in case are reported as differences.
- **Operational attributes** (`entryUUID`, `entryCSN`, `createTimestamp`, `memberOf`, `pwd*`, ...) are never cloned or compared. Adding one to the allow list is an error.
- **Rename and move detection** uses `entryUUID`, which the target assigns itself, so it needs the mapping file (`[mapping] file`) that `clone` records, exactly as for AD.

## Limitations

- Only users, groups and OUs are cloned, as for AD. Other object classes are reachable through custom per-kind `[scope.filters]` and `[attributes]`, but entries must fit one of the three kinds.
- Servers with a very different schema (no `inetOrgPerson`, for example) need `[scope.filters]` and `[attributes.include]` for each kind.
- Tested with OpenLDAP 2.4 (`osixia/openldap`). Other servers follow the same RFCs but have not been tested.
- Access control: the bind DN must be able to read everything under `base_dn` on the source and write it on the target.
- Cloning between an AD and a generic server is not supported.

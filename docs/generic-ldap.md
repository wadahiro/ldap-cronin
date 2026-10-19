# Generic LDAP servers (OpenLDAP, 389 Directory Server, ...)

ldap-cronin clones and compares any RFC 4510 directory, not only Active Directory. The `ldap` profile is chosen for every server that is not an AD; how it differs from the `ad` profile is in the [table in the README](../README.md#server-types-profiles).

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
# [mapping]
# mode = "preserve"        # the default here: keep the source's entryUUID with the relax control (OpenLDAP)
# operational = true       # also copy createTimestamp, modifyTimestamp, creatorsName, modifiersName
```

The **root** is the top of the naming context that holds `base_dn`. It must exist on the target and is never created or changed. It is taken from `root_dn`, otherwise from the longest `namingContexts` value above `base_dn`, otherwise from the trailing `dc=` components of `base_dn`.

## How it behaves

- **Groups that require a member.** `groupOfNames` must have at least one `member` when it is created. The tool first tries to create every entry without its DN references (they are applied afterwards, so creation order does not matter); if the server answers with an object class violation it retries with its references. Users are therefore created before groups.
- **Passwords.** The source's password hashes are never copied (`userPassword` is on the never-clone list). Cloned users get the fixed password you enter, sent as `userPassword` in the add that creates them, so the target must accept it under its password policy. A user is never created without it, and a re-run never touches the password of a user that already exists (the program under test may have changed it). Whether the server stores the plain value or a hash is the server's setting, as for a modify (389-ds hashes it; OpenLDAP does with `ppolicy_hash_cleartext`).
- **Every member is kept.** A referenced entry outside the scope that is of a kind (a user outside `base_dn`) is cloned as that kind, without its own references (`[scope] references = "clone"`, the default); any other value (an application account under `ou=Services`) is written as it is, since a generic server takes any DN. `diff` therefore sees a member removed or added, whatever it names.
- **Entries under a user or group.** A generic server has no structure rules, so a group may sit under a user. Such a parent is cloned as the user it is (with `sn` and the password), before its children, and compared once; one outside the scope (above `base_dn`) is cloned the same way, without its own references, like a referenced entry.
- **Comparison.** Values are compared exactly, except DN-valued attributes (case and escaping are normalized) and `objectClass` (case-insensitive). Case-insensitive attributes such as `mail` or `cn` that differ only in case are reported as differences.
- **Operational attributes** (`entryUUID`, `entryCSN`, `createTimestamp`, `memberOf`, `pwd*`, ...) are never cloned or compared. Adding one to the allow list is an error.
- **Rename and move detection, and production-like metadata.** By default (`[mapping] mode = "preserve"`) every Add carries the source's `entryUUID` and the relax control, so the target object's identifier is the source's and `diff` matches objects by it; nothing is stored beside the target. The same Add copies `createTimestamp`, `modifyTimestamp`, `creatorsName` and `modifiersName`, so the clone looks like production (`operational = false` skips them); they are never compared. The relax control is OpenLDAP's (an expired Internet-Draft, not advertised in the root DSE) and needs `manage` access to the entries or the rootdn: without it `clone` stops with that remedy rather than create objects with new identifiers. Other servers (389-ds is not verified) can use a marker attribute of an extended schema (`mode = "marker"`, `attribute = "..."`) or a local file (`mode = "file"`). See [docs/diff.md](diff.md#how-rename-and-move-detection-works-and-its-configuration).

## Limitations

- Only users, groups and OUs are cloned, as for AD. Other object classes are reachable through custom per-kind `[scope.filters]` and `[attributes]`, but entries must fit one of the three kinds.
- Servers with a very different schema (no `inetOrgPerson`, for example) need `[scope.filters]` and `[attributes.include]` for each kind.
- Tested with OpenLDAP 2.6 (the lab image, `docker/ldap`), including a non-rootdn account with `manage` access. Other servers follow the same RFCs but have not been tested.
- Access control: the bind DN must be able to read everything under `base_dn` on the source and write it on the target.
- Cloning between an AD and a generic server is not supported.

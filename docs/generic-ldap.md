# Generic LDAP servers (OpenLDAP, 389 Directory Server, ...)

ldap-cronin clones and compares any RFC 4510 directory, not only Active Directory. The `ldap` profile is chosen for every server that is not an AD; how it differs from the `ad` profile is in the [table in the README](../README.md#server-types-profiles).

The profile is `auto` by default. Set `[scope] profile = "ldap"` (or `"ad"`) to override the detection. With `auto` the target is checked too, and a source and target of different types are refused.
By default every attribute a client can write is copied ([below](#how-it-behaves)); `ldap-cronin list-attrs -profile ldap` prints the allow lists of `mode = "allowlist"`; `check -config config.toml` reads the source and the target and says which attributes the entries hold that `clone` leaves behind and what the target's schema lacks (`-attrs`: every attribute of every kind).

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
# [attributes]
# mode = "allowlist"       # copy the allow lists only (default: every attribute a client can write)
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
- **Every attribute a client can write, by default.** A generic server's entries are of no single class per kind (an `inetOrgPerson` that is a `posixAccount` and a `shadowAccount` too), so `clone` reads the object classes the entries of each kind in scope hold, in one more pass over them that reads `objectClass` alone, and copies, and `diff` compares, what those classes and the classes above them (`SUP`) name in `MUST` and `MAY` in the source's subschema; `extensibleObject` allows every attribute. Left out: what only the server writes (`NO-USER-MODIFICATION`), operational attributes (`USAGE` other than `userApplications`, which `*` does not return), what is never cloned (operational, below; the passwords) and the marker; `[attributes] exclude` takes more out. A kind's default allow list (`list-attrs -profile ldap`) comes along, as far as the source's schema defines it, so an entry a reference brings in from outside the scope gets what its class needs even if no entry in scope is of its kind; one of classes no entry in scope holds gets the attributes of those classes only through the default list. The source's `entryUUID` and creation metadata are not attributes of the lists: `[mapping] mode = "preserve"` (the default) sends them once, in the Add (below). An attribute the target's subschema lacks is left out with a note instead of stopping `clone`: give the target the schema (the OpenLDAP lab: `lab up --schema-dir`, [lab.md](lab.md#the-openldap-lab---profile-ldap)).
- **Or allow lists** (`[attributes] mode = "allowlist"`): the profile's lists (`list-attrs -profile ldap`), with `extra_include`, `include.<kind>` and `exclude`. An attribute of a schema extension is cloned once a list names it; `clone` then refuses to start if the target's subschema lacks one the source's has, naming them.
- **Comparison.** Values are compared exactly, except DN-valued attributes (case and escaping are normalized) and `objectClass` (case-insensitive). Case-insensitive attributes such as `mail` or `cn` that differ only in case are reported as differences.
- **Operational attributes** (`entryUUID`, `entryCSN`, `createTimestamp`, `memberOf`, `pwd*`, ...) are never cloned or compared. Adding one to the allow list is an error.
- **Rename and move detection, and production-like metadata.** By default (`[mapping] mode = "preserve"`) every Add carries the source's `entryUUID` and the relax control, so the target object's identifier is the source's and `diff` matches objects by it; nothing is stored beside the target. The same Add copies `createTimestamp`, `modifyTimestamp`, `creatorsName` and `modifiersName`, so the clone looks like production (`operational = false` skips them); they are never compared. The relax control is OpenLDAP's (an expired Internet-Draft, not advertised in the root DSE) and needs `manage` access to the entries or the rootdn: without it `clone` stops with that remedy rather than create objects with new identifiers. Other servers (389-ds is not verified) can use a marker attribute of an extended schema (`mode = "marker"`, `attribute = "..."`) or a local file (`mode = "file"`). See [docs/diff.md](diff.md#how-rename-and-move-detection-works-and-its-configuration).

## Limitations

- Only users, groups and OUs are cloned (AD also has computers and contacts). Other object classes are reachable through custom per-kind `[scope.filters]` and `[attributes]`, but entries must fit one of the three kinds.
- Servers with a very different schema (no `inetOrgPerson`, for example) need `[scope.filters]` for each kind (and, with allow lists, `[attributes.include]`).
- Tested with OpenLDAP 2.6 (the lab image, `docker/ldap`), including a non-rootdn account with `manage` access. Other servers follow the same RFCs but have not been tested.
- Access control: the bind DN must be able to read everything under `base_dn` on the source and write it on the target.
- Cloning between an AD and a generic server is not supported.

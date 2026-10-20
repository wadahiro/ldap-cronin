# Active Directory (a real AD, Samba AD)

The `ad` profile clones and compares Active Directory and Samba4 AD. It is chosen when the root DSE's `supportedCapabilities` contains `1.2.840.113556.1.4.800`; how it differs from the generic profile is in the [table in the README](../README.md#server-types-profiles).
`ldap-cronin list-attrs -profile ad` prints the default attributes (the ones Samba4 has out of the box); `ldap-cronin list-attrs -config config.toml` reads the source and lists the attributes its entries actually hold, and which of them `clone` leaves behind.
For a first run, the [tutorial](tutorial-ad.md) goes through a complete configuration and a clone into the lab and
into a test AD.

## Configuration

```toml
[source]
url = "ldaps://src-ad.example.com:636"
bind_dn = "CN=Administrator,CN=Users,DC=ad,DC=example,DC=com"
# ca_file = "ca.pem"                # the CA of a self-signed or internal certificate
[target]
url = "ldaps://dst-ad.example.com:636"   # LDAPS: required to set passwords
bind_dn = "CN=Administrator,CN=Users,DC=ad,DC=example,DC=com"
[scope]
base_dn = "OU=IDM,DC=ad,DC=example,DC=com"   # not the domain root: it would reach the built-in accounts
# [mapping]
# mode = "marker"                   # the default here: clone writes a marker of the source object
# attribute = "adminDisplayName"    # the attribute that holds it
```

[`config.example.toml`](../config.example.toml) has every key. A source and target must both be AD; cloning between an AD and a generic server is not supported.

## How it behaves

- **Users are created in three steps**: add (disabled), set `unicodePwd` with a modify, then set `userAccountControl` to the source's value (without the bits the server manages). A real AD accepts `unicodePwd` only in a modify, never in the add ([KB 269190](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/change-windows-active-directory-user-password)), and `userAccountControl` comes last because a disabled or never-expires flag changes the preconditions of setting the password. A re-run sets the password only for a user whose creation stopped before it (`pwdLastSet=0`), so it never rolls back a password the program under test changed.
- **Built-in objects are never touched**: everything with `isCriticalSystemObject=TRUE` (Administrator, krbtgt, ...) is excluded, even when `base_dn` is `CN=Users`.
- **Kinds.** Users are `(&(objectCategory=person)(objectClass=user))`, which leaves computers and contacts out; groups are `(objectClass=group)`; computers are `(objectCategory=computer)`, which leaves managed service accounts out; contacts are `(objectClass=contact)`. All five kinds (with `ou`) are cloned unless `[scope] objects` lists fewer.
- **Computers are accounts too.** A computer is added as a disabled workstation trust that needs no password (`userAccountControl` 4130), gets the fixed password, and then its source `userAccountControl` (4096 for a workstation), so its account type is the source's from the add on. A joined computer has a password, so the clone has one too; it is not the machine's, so the lab computer cannot log on as the real one. Its LAPS passwords, shadow credentials (`msDS-KeyCredentialLink`), resource-based delegation and gMSA password are never cloned. The values the machine refreshes by itself (`msDS-SupportedEncryptionTypes`, `lastLogonTimestamp`) are not in the defaults, so a live source does not differ on every diff.
- **Never cloned**: identifiers and server-managed attributes (`objectGUID`, `objectSid`, `sIDHistory`, `whenCreated`, `uSNChanged`, `memberOf`, `pwdLastSet`, the password hashes, ...). Listing one in `[attributes]` is an error.
- **Every member is reproduced where AD allows it.** A linked attribute such as `member` can only name an object the target holds, so for each value outside the scope clone:
  - clones the object if it is of a kind (a user or group outside `base_dn`), without its own references (`[scope] references = "clone"`, the default);
  - references a built-in the target holds as it is (`Domain Admins` of the same domain), but never creates one;
  - adds a well-known principal (Everyone, Authenticated Users, ...) by SID (`<SID=S-1-5-11>`), so the target's DC creates its own foreign security principal;
  - skips anything else with a warning (a principal of a trusted domain, which a test domain does not trust; a built-in the target lacks); `diff` counts these instead of comparing them.
- **Attributes of a schema extension** (your own, or a product's; `list-attrs -config config.toml -target` lists the ones your entries hold, and which the target lacks) are not cloned until an allow list names them (`extra_include`, `[attributes.include]`). Then the target needs them in its schema too: `clone` compares the two schemas before writing anything and refuses to start, naming each attribute the source defines and the target lacks, and the kinds whose lists name it. An attribute the target defines but a class does not allow (an auxiliary class the target lacks) fails at the first object with an object class violation, with the server's message. The Samba lab has the Exchange-compatible schema (`extensionAttribute1`-`15`, `msExch*`); `ldap-cronin schema` gives it the others before the first `clone` (it prints what the target lacks as LDIF; `-apply` writes it), and the snapshots taken after carry them. The [tutorial](tutorial-ad.md#attributes-of-your-own-schema-extensions) goes through it step by step.
- **`ldap-cronin schema`** compares the `attributeSchema` and `classSchema` entries of the two schema naming contexts by `lDAPDisplayName` and plans what the target lacks: the attributes, then the classes (after the class each derives from), then the values of the classes both have (`mayContain`, `auxiliaryClass`, `possSuperiors`, so `user` gets your auxiliary class), with a `schemaUpdateNow` after each step. The definitions keep the source's OIDs, `schemaIDGUID`, `linkID` and the rest a client sets; DNs move to the target's schema naming context. Left out, each with why: definitions of a newer Windows Server base schema than the target's (`systemFlags` 0x10; the lab's level is chosen when it is provisioned), a name or OID the target uses for something else, a `mustContain` a class the target has cannot be given, and what depends on those. Without `-apply` it writes nothing. A schema change cannot be undone in AD, so for a test AD write the file, review it and apply it as a member of Schema Admins, against the schema master (`-apply` with `[target] url` on the schema master does the same; another DC refuses the change).
- **`[attributes] mode = "all"`** copies and compares every attribute the source's schema lets a client write on the class of each kind (`organizationalUnit`, `group`, `user`, `computer`, `contact`): what the class, the classes it derives from and their auxiliary classes may or must contain, without `systemOnly` attributes, constructed ones, back links, DN-Binary/DN-String values, what is never cloned (identifiers, credentials) and the marker; `exclude` still applies. An attribute the target's schema lacks is left out with a note instead of stopping `clone` (run `ldap-cronin schema` first for your extensions); a dry-run does not read the target, so its LDIF has them all. An auxiliary class attached to single objects (not in the schema) is not followed: name its attributes by switching back to the allow lists. Some attributes AD lets a client write still belong to the server in practice (the ones a DC refreshes on its own, such as `msDS-SupportedEncryptionTypes` of a live computer): they are copied once and may differ later; `exclude` them if they get in the way.
- **DN-valued attributes** are found in the source schema (`attributeSyntax=2.5.5.1`), so an attribute added with `extra_include` is handled too. `member` is always read in explicit ranges, as AD splits large groups ([operations.md](operations.md#large-data-sets)).
- **Comparison** normalizes `userAccountControl` (server-managed bits) and `accountExpires` (`0` and `9223372036854775807` both mean "never"); see [diff.md](diff.md#what-is-compared).
- **What a Samba target refuses.** Samba will not have `userParameters` written over LDAP ([bug 8077](https://bugzilla.samba.org/show_bug.cgi?id=8077); Windows takes it). When the target's root DSE says it is Samba (`vendorName`, which Windows does not publish), `clone` and `diff` leave it out, in any mode, and name it with the reason; `list-attrs -target` notes it. A dry-run does not connect to the target, so its LDIF still carries it.
- **Rename and move detection.** AD refuses a client-set `objectGUID` over LDAP, so `clone` writes a marker of the source object into `adminDisplayName` (`ldap-cronin:<source root>:<source key>`); how `diff` uses it is in [diff.md](diff.md#how-rename-and-move-detection-works-and-its-configuration). `clone -native` keeps the `objectGUID` itself, but only into the Samba lab ([lab.md](lab.md#importing-with-the-same-objectguid-and-objectsid-clone--native-samba-only)).

## When the target is a real AD

- Setting a user's password (`unicodePwd`) **requires LDAPS**. Over `ldap://` the password change is rejected (Samba does the same).
- The fixed password must satisfy the target domain's password policy (complexity and so on). Otherwise setting the password after creating the user fails, and the user stays disabled.
- The LDAP signing policy may reject a simple bind over `ldap://`. Use LDAPS or `start_tls`.
- For a self-signed or internal certificate, pass the CA with `ca_file`. For testing only, `insecure_skip_verify` is also available.
- **Index the marker attribute** before the first `clone`: set bit 1 in the `searchFlags` of its `attributeSchema` entry (`CN=Admin-Display-Name,CN=Schema,CN=Configuration,...` for `adminDisplayName`). Without it `clone` warns, and every search for a moved object reads the whole naming context. The lab image does this by itself.
- Writes are replicated to the other DCs. Run against a test domain, outside business hours; the load per user is in [operations.md](operations.md#load-on-the-target-ad-clone).

## Limitations

- Only OUs, groups, users, computers and contacts are cloned. Other object classes (BitLocker recovery information, password settings objects, managed service accounts, GPOs) are reachable only through custom per-kind `[scope.filters]` and `[attributes]`; a member of such a class is skipped with a warning and counted by `diff`.
- Not yet verified on a real AD:
  - writing the marker with a delegated (non-admin) account;
  - interference with the marker attribute by Exchange, Entra Connect or ADUC's "copy user";
  - adding a computer with `userAccountControl` 4130 and then setting 4096 (verified on Samba);
  - the effect of `workers` on a real AD (measured on Samba only, see [operations.md](operations.md#performance-figures-measured-with-samba4-as-the-target)).
- `clone -native` (the same `objectGUID` and `objectSid`) works only into the Samba lab: Windows AD does not let a client choose an `objectGUID`.

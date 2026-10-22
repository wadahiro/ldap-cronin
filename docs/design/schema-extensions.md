# Schema extensions: carry them to the target, and copy every attribute

Status: implemented (`ldap-cronin schema`, `[attributes] mode = "all"`; AD only).

## 1. Goal

A production AD holds attributes the lab lacks: an organization's own extension, a product's (Exchange, Entra
Connect), a newer Windows Server's. Two things were manual:

1. **Giving the target their definitions.** The tutorial had the reader search the source's schema and write the
   `attributeSchema` / `classSchema` LDIF by hand.
2. **Copying them.** The allow lists name what Samba has out of the box; everything else had to be found with
   `check` and listed in `extra_include`.

## 2. `ldap-cronin schema`

- Reads every non-defunct `attributeSchema` and `classSchema` of both schema naming contexts and matches them by
  `lDAPDisplayName` (`internal/ad/schema.go`).
- Plans, in this order, with `schemaUpdateNow` after each step: the attributes the target lacks; the classes it
  lacks, by depth of `subClassOf` among the new ones; the values of `mayContain`, `auxiliaryClass` and
  `possSuperiors` (and their `system*` counterparts) that a class both have holds on the source only, added to the
  non-system attribute, with the new classes' references to each other. Deferring those references keeps the
  order a tree (no cycles through `possSuperiors`).
- Writes what a client sets on creation: OIDs, syntax, `schemaIDGUID`, `attributeSecurityGUID`, `linkID`, `mAPIID`,
  `searchFlags`, ranges, `systemOnly` (a back link carries `TRUE`), the class's `defaultSecurityDescriptor` and
  `defaultObjectCategory` (moved to the target's naming context). The `system*` fields of a new class are folded
  into their counterparts. What the server assigns (`msDS-IntId`, `systemFlags`) is not written.
- Leaves out, with why: base schema definitions (`systemFlags` 0x10) — a server's level is chosen at installation;
  names or OIDs used for something else on the target; a `mustContain` for a class the target has, which AD
  forbids; and anything that depends on one of those. A value naming something already listed is not listed again.
- Prints LDIF for `ldapmodify` / `ldifde` by default; `-apply` writes through the target connection. `clone` never
  calls it: a schema change cannot be undone in AD.

Verified on Samba 4.19: an explicit `schemaIDGUID`, `oMObjectClass`, a forward/back link pair, `systemOnly: TRUE`,
a new auxiliary class and structural class, `auxiliaryClass` added to `user` and `mayContain` to `group`. Not yet
verified against Windows AD.

## 3. `[attributes] mode = "all"`

- Resolved once in `app.Open` from the source schema: for each kind's class (`KindSpec.Class`), what it, the classes
  it derives from and their auxiliary classes must or may contain, without `systemOnly`, constructed
  (`systemFlags` 0x4), back links (odd `linkID`), `NeverClone`, the credentials, the
  identifier and the marker; then `exclude`. The result is a static allow list, so the target schema check, the
  references, the comparison and the summaries work as before.
- In clone and diff (not a dry-run), the attributes the target's schema lacks are dropped with a note instead of
  refusing: no one named them. The required attributes are never dropped.
- `include` / `extra_include` are refused with it.

Open:

- An auxiliary class attached to single objects is not followed.
- Attributes the server or the machine refresh (`msDS-SupportedEncryptionTypes`) are copied and may differ later.
- Generic LDAP: the subschema has the same information (`MAY`, `MUST`, `NO-USER-MODIFICATION`, `USAGE`) but the
  kinds there have several structural classes; neither feature exists for it yet.

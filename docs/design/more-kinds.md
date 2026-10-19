# Membership fidelity: every member on the target, and diff sees every change to it

Status: in progress. Steps 1 and 2 (3.1 to 3.5) are implemented; steps 3 to 5 follow: parent leaves (3.6), computers and contacts (3.7, 3.8), the counts (3.9).

## 1. Goal

A typical test on the clone: the program under test updates group memberships, and the tester checks that it
removed no member it should not have (and added none). That test holds only if

1. **every value of a group's `member` on the source is on the target** after clone, and
2. **diff compares every value**, so any removal or addition shows.

Neither holds today (section 2). This proposal makes both the default, and on the way:

- clones the objects a member can be: **computers** and **contacts** become AD kinds, and objects outside the
  scope that are referenced are cloned too (**referenced objects**);
- handles **entries under leaves** (a user or computer with children), which breaks today;
- reports what could not be reproduced, so the tester knows the limits of the test.

`member` is the motivating case; the same rules apply to every DN-valued attribute (`manager`, `managedBy`,
`seeAlso`, `uniqueMember`, ...).

## 2. Today

### 2.1 Members outside the scope are dropped, and diff hides it

- **clone** applies a reference value only if it names an object in the scope or one that already exists on the
  target; the rest are skipped with a warning. Computers, contacts, service accounts, foreign security principals
  and users outside `base_dn` are therefore missing from the target's groups.
- **diff** keeps only in-scope values on **both** sides before comparing (`resolveRefs`: `InScope(want)`,
  `InScope(got)`). A program that removes a computer from a group, or adds `Domain Admins` to one, produces no
  difference.

A group member can be, on AD (that `member` accepts any object over LDAP is unverified; ADUC offers security
principals and contacts):

| Member | Typical use | Today |
|---|---|---|
| user, `inetOrgPerson`, group | the usual | cloned when in scope |
| computer | GPO security filtering, WSUS and LAPS reader groups | not a kind |
| contact | distribution groups | not a kind |
| `foreignSecurityPrincipal` | well-known identities (Authenticated Users) and accounts of trusted domains; the DC creates it in `CN=ForeignSecurityPrincipals` | cannot be cloned (created by the DC) |
| `msDS-(Group)ManagedServiceAccount` | resource access | not a kind |
| built-in group or user (`Domain Admins`) | nested built-ins | excluded (`isCriticalSystemObject`); exists on a target of the same domain |
| anything outside `base_dn`, or filtered out by `[scope.filters]` | company-wide groups | skipped |
| Exchange objects (mail-enabled public folders) | distribution groups | not a kind |

On a generic server `member` and `uniqueMember` take any DN: application accounts (`applicationProcess`,
`simpleSecurityObject`, `account` under `ou=Services`, the usual way OpenLDAP grants rights to an application),
`organizationalRole`, nested groups. OpenLDAP does not check that a member DN exists (unless an overlay does), so
skipping values that do not exist on the target applies an AD constraint to a server that does not have it.

### 2.2 A leaf with children

`plan.Build` scans containers with their attributes and leaves by DN only; every ancestor of a scanned entry that is
not a selected container becomes a **create-only ancestor** (created with `AncestorAttrs` when missing, otherwise
left alone). A leaf with a child in scope is handled twice. Probed with fakedir:

| Case | Result |
|---|---|
| Generic: a `groupOfNames` under `uid=alice` | **clone stops**: alice is added with the ancestor attributes only, without `sn` (object class violation). diff reports alice as `ONLY_SOURCE` twice |
| AD: a group under a user | Works by accident: the user is added without `sAMAccountName` or the account steps, the leaf pass updates it, and `pwdLastSet=0` makes it set the password. diff compares the user twice |

Production has such entries: Exchange puts `CN=ExchangeActiveSyncDevices` under users, AD puts BitLocker and TPM
information under computers, and a generic server has no structure rules at all. The diff side also assumes only
containers have children: the expected DN of a child of a moved parent comes from `EachLevel`, which handles only
containers shallowest first.

## 3. Design

### 3.1 What a reference value names

One function in `plan` classifies a reference value, and clone and diff both use it, so what clone could not
reproduce is exactly what diff does not compare:

| Class | Meaning | clone | diff |
|---|---|---|---|
| **in scope** | an entry clone selected | created, value applied | compared |
| **referenced object** | an entry outside the scope that maps to a kind (3.2) | created as that kind, value applied | compared |
| **existing** | not cloned, but present on the target at the same DN (a built-in of the same domain) | value applied | compared |
| **well-known principal** | an AD foreign security principal whose SID is well-known (3.3) | value applied by SID | compared |
| **value only** | a generic server that does not need the entry to exist (3.4) | value applied as it is | compared |
| **unreproducible** | none of the above (a built-in the target lacks, a principal of a trusted domain, an entry of no kind on AD) | skipped, counted | **not compared**, counted |

The classification of a value comes from the source and the target, not from a record of what clone did, so diff
needs no state and gives the same answer on any machine. A value is looked up once per run (cached as today).

### 3.2 Referenced objects

An entry outside the scope that an in-scope entry references is cloned too, **by default**:

- **Which kind.** The source entry is read once (`objectClass`, `objectCategory`) and matched against the kinds by
  class (a predicate next to each kind's filter in the profile: AD user = person + user, computer, contact, group,
  OU; generic inetOrgPerson, groupOfNames, ...). The kind's default filter decides, not `[scope.filters]`: the entry
  is by definition outside them. An entry the profile's system filter excludes (`isCriticalSystemObject`) is never
  created: it is **existing** or **unreproducible**.
- **Depth one.** A referenced object is created with its kind's attributes **without its own references**. Following
  them would pull the directory in (a company-wide group's members, their managers, ...). Its own references are
  neither applied nor compared, and the summary says so.
- **Where.** At its own DN; missing ancestors are created create-only, as for the scope. Users get the fixed password
  and the account steps, objects get the marker or the preserved identifier, as any clone.
- **When.** Scanned in `plan.Build`: the leaf scan reads the reference attributes too (values are streamed; only the
  set of DNs outside the scope is kept), then each such DN is classified. They are created after the scope's
  leaves and before the reference pass, shallowest first.
- **diff** compares them as their kind, without their references, and never reports them `ONLY_TARGET`.
- **Setting.** `[scope] references = "clone"` (default) | `"existing"` (today's behavior: apply only what exists on
  the target) | `"skip"`.
- **Cost.** One source read and one target read per distinct outside DN, and one entry created for each. An in-scope
  group with 50,000 members outside the scope creates 50,000 objects; the summary gives the count, and `existing`
  turns it off.

### 3.3 Foreign security principals (AD)

The DC creates a foreign security principal when a member is added by SID (`member: <SID=S-1-5-11>`). The source's
member value is `CN=<SID>,CN=ForeignSecurityPrincipals,<domain>`; clone adds `<SID=<SID>>` instead.

- Well-known SIDs (`S-1-1-0`, `S-1-5-11`, `S-1-5-4`, ...) exist in every domain: **well-known principal**.
- A SID of a trusted domain needs the trust on the target, which a test domain lacks: tried once, and on refusal
  **unreproducible** with a warning. Whether AD and Samba refuse it, or create the principal anyway, is
  **unverified** (e2e checks Samba).
- The target's DN of the principal is the same as the source's (the clone keeps the domain name), so diff compares
  the values as DNs.
- Found on Samba (e2e): for some SIDs (Everyone, `S-1-1-0`) the DC does not create a foreign security principal
  but stores `CN=Everyone,CN=WellKnown Security Principals,CN=Configuration,<forest>`, which every domain of that
  name holds: such a value is **existing**. Samba also refuses `<SID=...>` with 68 (entry already exists) when the
  principal already exists, so an existing principal is written by DN (existing comes before principal).

### 3.4 Whether a reference needs its entry

A profile property, `RefsNeedEntry`: true on AD (linked attributes must name an existing object), false on the
generic profile. With false, a value that is neither in scope nor a referenced object is **value only**: applied
as it is. A generic target with a referential-integrity overlay that refuses it reports the error; the remedy is
`references = "existing"`.

### 3.5 diff compares every value

`resolveRefs` stops filtering by scope. The target values are translated back for renames (as today). Only the
**source's** unreproducible values are left out (and counted): clone could not have put them there. Every target
value is compared, since it is on the target, so a removed computer, a removed principal, or an added
`Domain Admins` (or an added principal of a trusted domain) is a `DIFF` (`member: source only / target only`).

The summary states what was not compared:

```
references not compared (could not be cloned): member 20 (trusted-domain principals 18, built-ins missing on the target 2)
```

### 3.6 Parent leaves

A **parent leaf** is an entry of a leaf kind that is also the ancestor of an entry in scope (or of a referenced
object).

- `plan.Build` records the kind of every leaf it scans (the scope keeps a kind index per DN). An ancestor found in
  the scope as a leaf is not made create-only: it is read with its kind's attributes and added to `Containers` as
  `Node{Entry, Kind, Leaf: true}`.
- `EachLevel` hands a parent leaf to the caller's leaf function at its depth: clone runs the leaf path (account
  steps, marker, mapping), diff compares it as a leaf, and its children's expected DN is known when it moved.
- `EachLeaf` skips the DNs handled as parent leaves (a set of the parent leaves only).
- Children of no kind (ActiveSync devices, BitLocker) are not cloned and are counted (3.9).

### 3.7 `computer` (AD)

Computers are what most groups hold besides users (3.1), so they become a default kind.

| | |
|---|---|
| Filter | `(objectCategory=computer)`. Service accounts have their own `objectCategory` and stay out; the user filter (`objectCategory=person`) already leaves computers out |
| Role | Leaf, after users and groups. Not an account: no password; the computer is pre-staged |
| Default attributes | `sAMAccountName`, `userAccountControl`, `dNSHostName`, `description`, `displayName`, `location`, `managedBy`, `operatingSystem`, `operatingSystemVersion`, `operatingSystemServicePack`, `servicePrincipalName`, `info` |
| Never cloned (added to `NeverClone`) | LAPS (`ms-Mcs-AdmPwd`, `ms-Mcs-AdmPwdExpirationTime`, `msLAPS-Password`, `msLAPS-EncryptedPassword`, `msLAPS-EncryptedPasswordHistory`, `msLAPS-EncryptedDSRMPassword`, `msLAPS-PasswordExpirationTime`), `msDS-KeyCredentialLink`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-ManagedPassword`. `primaryGroupID` already is (the DC sets 515) |
| Not in the default list | `msDS-SupportedEncryptionTypes` and other values the machine refreshes (a live source would differ on every diff); `userCertificate` (binary, a credential) |

`userAccountControl` is copied without the bits the server manages (a workstation is 4096). Whether a real AD
accepts a computer added with 4096 and no password is **unverified**; if not, it is created with `PASSWD_NOTREQD`
(32) added and set to the source value afterwards, as the account steps do for users.

### 3.8 `contact` (AD)

`(objectClass=contact)`, a leaf, not an account. Default attributes: the user list without the account and logon
attributes (`sAMAccountName`, `userPrincipalName`, `userAccountControl`, `accountExpires`, `homeDirectory`,
`homeDrive`, `scriptPath`, `profilePath`, `uidNumber`, `gidNumber`, `loginShell`, `unixHomeDirectory`).

### 3.9 What was not cloned

`clone` and `diff` print, in their summaries:

```
referenced objects cloned: 312 (user 280, group 30, computer 2)
not cloned (matches no kind): msFVE-RecoveryInformation 120, msExchActiveSyncDevice 14, serviceConnectionPoint 3
references not compared (could not be cloned): member 20 (trusted-domain principals 18, built-ins missing on the target 2)
```

- The second line is one extra paged search per run: `(!(|<every kind's filter>))` under `base_dn`, reading only
  `objectCategory` (AD) or `structuralObjectClass` (generic). Counts only.
- Create-only ancestors (CN= containers) are created, so they are not counted. A kind left out with
  `[scope] objects` is counted.

### 3.10 Kept out of the defaults

| Objects | Why |
|---|---|
| `msFVE-RecoveryInformation`, `msTPM-*` | BitLocker recovery passwords and TPM owner information of production machines |
| `msDS-PasswordSettings` (PSO) | Changes the target's password policy, which the fixed password must satisfy |
| `msDS-(Group)ManagedServiceAccount` | Needs a KDS root key on the target; creating one over LDAP is unverified, and it changes the target's behavior. As a member it is **unreproducible**, and counted |
| `groupPolicyContainer`, OU `gPLink` | The policy files are not in LDAP; a cloned GPO is a shell and `gPLink` names GPOs the target lacks |
| `serviceConnectionPoint`, `connectionPoint` | Carry production service endpoints a program under test could call |

They are not kinds, so they are not referenced objects either: they show in the counts.

### 3.11 Configuration

- `[scope] objects` defaults to every kind of the profile: on AD `ou`, `group`, `user`, `computer`, `contact`.
- `[scope] references = "clone" | "existing" | "skip"` (3.2).
- `[scope.filters]` and `[attributes.include]` accept the new kind names.
- Compatibility is not a concern; the README and `config.example.toml` say that computers, contacts and referenced
  objects are now cloned by default.

## 4. Changes to the code

| Where | Change |
|---|---|
| `internal/profile` | `KindComputer`, `KindContact`; a class predicate per kind; `RefsNeedEntry`; well-known SIDs and the `<SID=>` form; `NeverClone` additions; kind order |
| `internal/plan` | Scope with a kind index; the leaf scan reads reference attributes and collects outside DNs; the reference classification (3.1); referenced objects and parent leaves in the plan; `Unselected(ctx)` for the counts |
| `internal/clone` | Parent leaves in the level pass; referenced objects created before the reference pass; values applied per class (by SID for principals) |
| `internal/diff` | Parent leaves; referenced objects compared without references; `resolveRefs` compares every reproducible value; summary lines |
| `internal/config` | `references`; the new kind names |
| `docker/ad/seed.sh`, `docker/ldap/seed.ldif` | A group with a computer, a contact, a user outside `base_dn`, Authenticated Users and a built-in as members; a group under a user; on LDAP an application account as a member |
| Docs | README, `docs/active-directory.md`, `docs/generic-ldap.md`, `docs/diff.md` (references are compared in full; the summary lines), `config.example.toml` |

## 5. Tests

- **The membership test itself**, per member class (user, computer, contact, referenced user outside `base_dn`,
  well-known principal, built-in, value only): clone, then the "program" replaces `member` with a subset, then
  diff reports exactly the removed values; adding `Domain Admins` (or any outside value) is reported too. Values
  that are unreproducible are counted and not reported.
- Referenced objects: created as their kind with the account steps, without their own references; ancestors
  created; never `ONLY_TARGET`; `references = "existing"` and `"skip"` behave as named; one read per outside DN.
- Parent leaves, both profiles: the generic case no longer stops; the user is compared once; a moved parent leaf puts
  its children at the expected DN.
- Computers: the filter excludes service accounts; the never-cloned attributes are refused in an allow list and
  absent from the LDIF; `userAccountControl` 4096 round-trips.
- The fault-injection, random-tree and dry-run LDIF tests get referenced objects, parent leaves, computers and
  contacts.
- e2e (Samba and OpenLDAP): the seeded memberships clone completely and diff clean; removing each kind of member
  is a `DIFF`; the `<SID=>` add on Samba (well-known, and an unknown domain SID).

## 6. Alternatives rejected

| Alternative | Why not |
|---|---|
| Clone every object by default | Section 3.10: secrets and objects that change the target; Exchange and LAPS classes the target schema lacks |
| A catch-all `other` kind | One allow list cannot fit classes with different `mustContain`; the counts say which kind to add instead |
| Follow references transitively | Pulls in the directory through company-wide groups; depth one reproduces every value of the scope's references |
| Compare out-of-scope values only as DN strings, without cloning their objects | Works on generic servers (3.4) but not on AD, where the value cannot exist without the object; and the program under test may read the member's entry |
| Record at clone time what was not reproduced, for diff | A state file beside the target again (see mapping-ledger.md); the classification is deterministic from the source and the target |
| Copy every client-settable attribute (`[attributes] mode = "all"`) | Feasible later from the schema walk, as an explicit mode with a "dropped on target" report; not the default because of confidential attributes and target schemas |

## 7. Open questions (unverified)

- `member: <SID=...>` on Samba and AD: well-known SIDs, and a SID of a domain the target does not trust.
- A computer added with `userAccountControl` 4096 and no password on a real AD (3.7).
- Whether AD's `member` accepts any object class over LDAP (only matters for objects of no kind, which are
  unreproducible either way).

<!-- Output and comparison rules of ldap-cronin diff. Referenced from README.md. -->

# diff output and comparison rules

`diff` compares the source (the clone origin) with the target and finds **changes made on the target after the clone**.
It is read-only.

```sh
./bin/ldap-cronin diff -config config.toml                  # exit code 1 if there are differences
./bin/ldap-cronin diff -config config.toml -format json > diff.jsonl   # for a program: JSON Lines (see below)
./bin/ldap-cronin diff -config config.toml -max-values 10   # shorter: at most 10 values per direction
```

- Exit codes: no differences **0** / differences found **1** / error **2**.
- Differences are streamed to standard output as found, so the order of entries is not fixed. Within an entry, attributes follow allow-list order and multi-valued values are sorted.
- A summary of the compared scope follows ([how to read the summary](#how-to-read-the-summary)).

## What is compared

`diff` reads the same configuration file as clone and compares **only the attributes that are copied**.

- What is compared is the final allow list (per object type) after applying `include` / `extra_include` / `exclude` in `[attributes]`.
  An attribute that is `exclude`d or not in the allow list does not produce a difference even if its values differ (`ldap-cronin list-attrs` shows the default allow list).
- **Masked attributes are not compared** (the target holds a fixed string, so the values are expected to differ). Password-related attributes (`unicodePwd`, `dBCSPwd`, `ntPwdHistory`, `lmPwdHistory`, `supplementalCredentials`) are not compared either (they cannot be read over LDAP).
- Values are compared by **exact match** (case-sensitive). The following are normalized before comparing: attributes whose values are DNs (case and escaping),
  `objectClass` (case), `userAccountControl` (excluding server-managed bits) and `accountExpires` (`0` and `9223372036854775807` both mean "never expires" and are treated as equal).
  Multi-valued attributes are compared ignoring order.
- DN reference attributes (`member`, `manager` and so on) are **compared in full**, so a program under test that removes or adds a member shows, whatever the member is (an object of the scope, a built-in group, an object outside `base_dn`). Objects outside the scope that the references name are cloned and compared too, as their kind and without their own references (`referenced objects outside the scope compared: N`). The only values left out are the source's values `clone` cannot write: on AD, a reference to an object the target does not hold and clone cannot create (a built-in the target lacks, a principal of a trusted domain). The summary counts them per attribute (under `references not compared ...`).
- Entries under `base_dn` of no kind (BitLocker recovery information, a service connection point, a kind left out of `[scope] objects`) are not cloned, so they are not compared either; the summary counts them per object class, one per line (under `not compared (matches no kind, ...)`). `clone` prints the same counts (`not cloned (matches no kind)`), and the objects it cloned from outside the scope per kind (`referenced objects outside the scope cloned`).
- The objects compared are those that match `[scope] objects` and `[scope.filters]`.
- Use the same configuration file for clone and diff; different settings change the result (an `exclude` added only for diff hides that attribute).

## Kinds of output

| Kind | Meaning | Needs object matching |
|---|---|---|
| `ONLY_SOURCE` | Only in the source, not on the target (not cloned yet, or deleted on the target) | No |
| `ONLY_TARGET` | Only on the target, not in the source (newly created on the target) | No |
| `DIFF` | Present on both sides, but attribute values differ | No |
| `RENAMED` | The same object has a different DN on the target (renamed or moved) | Yes |
| `REPLACED` | A different object than the cloned one exists at the same DN (its identifier or marker names another object), and the original is nowhere to be found | Yes |
| `UNMARKED` | The object at the source DN has no marker (marker mode only): recreated, marker removed, or added to the source after the clone | Yes |

Object matching tells which source object a target object was cloned from; it is on by default ([how it works](#how-rename-and-move-detection-works-and-its-configuration)). Without it, see [when matching is off](#6-when-matching-is-off). Every kind, `RENAMED`, `REPLACED` and `UNMARKED` included, makes the exit code 1: a rename alone is a change made on the target.

## Patterns: what happened on the target and how it appears

Examples use `base_dn` = `OU=IDM,DC=example,DC=com`.

### 1. Attribute value differences (`DIFF`)

**1-1. Single-valued attributes**: `source` and `target` are lined up vertically (the values start at the same column), and a wavy line (`~`) is drawn under the differing span after removing the common prefix and suffix.
Where one side has extra characters, a `^` marks the position of the added characters. Full-width characters (such as Japanese) count as 2 columns.

```
DIFF        CN=Alice,OU=Users,OU=IDM,DC=example,DC=com
            department:
              source: Sales Dept
                             ~~~
              target: Sales Div
                             ~~
```

**1-2. A value missing on one side** (an attribute added or removed): the missing side shows `(none)`. No wavy line is drawn.

```
DIFF        CN=Alice,OU=Users,OU=IDM,DC=example,DC=com
            description:
              source: (none)
              target: changed by another program
```

**1-3. Differences in letter case only**: `(case only)` is added next to the attribute name, and the wavy line is drawn only under the characters that differ.
It still counts as a difference (exit code 1); the summary shows `of which case only: N`.

```
DIFF        CN=Alice,OU=Users,OU=IDM,DC=example,DC=com
            mail:  (case only)
              source: Alice@Example.com
                      ~     ~
              target: alice@example.com
                      ~     ~
```

**1-4. Multi-valued attributes** (such as `member`): instead of all values, it shows "which side has it only", one value per line.

```
DIFF        CN=Eng,OU=Groups,OU=IDM,DC=example,DC=com
            member:
              only in source (2):
                - CN=Bob,OU=Users,OU=IDM,DC=example,DC=com
                - CN=Carol,OU=Users,OU=IDM,DC=example,DC=com
              only in target (1):
                - CN=Mallory,OU=Users,OU=IDM,DC=example,DC=com
```

If the other side has a value that differs only in case, `(case only: same value on ... side)` is added to that value.

```
DIFF        CN=Alice,OU=Users,OU=IDM,DC=example,DC=com
            proxyAddresses:
              only in source (2):
                - SMTP:Alice@Example.com    (case only: same value on target side)
                - smtp:a.admin@example.com
              only in target (2):
                - SMTP:alice@example.com    (case only: same value on source side)
                - smtp:alice.admin@example.com
```

Every value is shown by default: a cut list could hide the one removal a test looks for. `-max-values <n>` shows at most `n` per direction and the rest as `... (+N more; ...)`. Example with `-max-values 2`:

```
DIFF        CN=Eng,OU=Groups,OU=IDM,DC=example,DC=com
            member:
              only in target (5):
                - CN=User1,OU=Users,OU=IDM,DC=example,DC=com
                - CN=User2,OU=Users,OU=IDM,DC=example,DC=com
                ... (+3 more; use -max-values to show more)
```

**1-5. DN reference attributes** (`member`, `manager`, `managedBy`, and anything added through `extra_include` such as `seeAlso`; detected automatically from the source schema):
DN case and escaping (`\,` versus `\2C`) differences are not reported; source values `clone` cannot write are left out first (see [What is compared](#what-is-compared)).

### 2. Presence of objects (`ONLY_SOURCE` / `ONLY_TARGET`)

Deleted on the target: `ONLY_SOURCE`; newly created: `ONLY_TARGET`.

```
ONLY_SOURCE CN=Dave,OU=Users,OU=IDM,DC=example,DC=com
ONLY_TARGET CN=Newcomer,OU=Users,OU=IDM,DC=example,DC=com
```

The same applies under a moved OU: a child deleted after the move is `ONLY_SOURCE`, a new one is `ONLY_TARGET`.

### 3. Rename and move (`RENAMED`)

The DN of an object was changed on the target; the unchanged identifier (`objectGUID`, or `entryUUID` on a generic server) identifies it, or the marker clone wrote into it.
`(renamed)` means the RDN changed, `(moved)` means the parent changed, and both together give `(renamed and moved)`. **Objects moved outside the starting point (`base_dn`) are detected too.**

```
RENAMED     source: CN=Cid,OU=Users,OU=IDM,DC=example,DC=com
            target: CN=Cid Renamed,OU=Users,OU=IDM,DC=example,DC=com   (renamed)
RENAMED     source: CN=Bob,OU=Dept,OU=Users,OU=IDM,DC=example,DC=com
            target: CN=Bob,OU=Archive,OU=IDM,DC=example,DC=com   (moved)
RENAMED     source: CN=Eve,OU=Dept,OU=Users,OU=IDM,DC=example,DC=com
            target: CN=Eve Smith,OU=Archive,OU=IDM,DC=example,DC=com   (renamed and moved)
```

**Even when a rename or move is detected, attributes are still compared.** Any difference follows as a `DIFF` under the current DN on the target.
However, changing the RDN makes the server change `cn` (or `ou` for an OU) as well, so that part is not reported as a result of the rename
(if the target value disagrees with the new RDN, it is reported as a real difference).

### 4. OU moves and renames, and what is under them

Moving or renaming an OU changes the DN of everything under it, so
**children that are fully explained by the parent OU's move are not listed** (only the OU itself appears). The summary shows the count as `not listed: N entries moved along with a renamed/moved parent OU`.

The same holds for a user or group that has children (a group under a user, which a generic server allows): its rename or move is reported once, for it alone.

Only children found by identifier that moved with the parent as expected are left out. These **are** shown:

| What happened on the target | What is shown |
|---|---|
| A child that moved with its parent had an attribute changed | `DIFF` under the current DN on the target (only the fact of the move is left out) |
| A child moved to a different place than its parent | `RENAMED` (`moved`) for that child |
| A child was renamed (RDN) inside the moved parent | `RENAMED` (`renamed`) for that child; it is not called a move |
| A child was deleted after the OU was moved | `ONLY_SOURCE` |
| A new object was created under the moved OU | `ONLY_TARGET` |

**With nested OUs (an OU under an OU, with users below)**, the tool works from the shallowest level down, locating each parent on the target to judge its children.

| What happened on the target | What is shown |
|---|---|
| A parent OU and everything under it (child OUs, users) moved together | Only `RENAMED` for the parent OU (child OUs and users are not shown, only counted) |
| A parent OU and a child OU were renamed separately | `RENAMED` (`renamed`) for each of the parent and child OUs. Grandchildren are not shown |
| The parent OU moved, and a child OU alone moved out of the parent | `renamed` for the parent OU, `moved` for the child OU. Nothing under the child OU is shown |
| The parent OU did not move, and a child OU alone moved elsewhere | Only `RENAMED` (`moved`) for the child OU |
| A user inside the nested OUs alone moved somewhere completely different | `RENAMED` (`moved`) for that user |

### 5. A different object recreated at the same DN

**5-1. Deleted and recreated at the same DN** (the original is nowhere to be found).
With markers (AD), the new object has no marker, so diff cannot say whether it was recreated, had its marker removed, or was added to the source after the clone: `UNMARKED`.
With preserved identifiers (generic LDAP, `clone -native`) or a mapping file, its identifier differs from the cloned one: `REPLACED`. An object whose marker names *another* source object (a marker copied by the program under test) is `REPLACED` too.
**Attributes are still compared, to see how the object differs from the source values** (a `DIFF` follows if there are differences).

```
UNMARKED    CN=Eve,OU=Users,OU=IDM,DC=example,DC=com
            no marker: recreated, marker removed, or added to the source after the clone
DIFF        CN=Eve,OU=Users,OU=IDM,DC=example,DC=com
            description:
              source: (none)
              target: recreated by another program
```

**5-2. An OU with the same name was recreated after the OU was moved**: the original OU is still alive elsewhere, so it is not called `REPLACED`.
Instead the original OU is shown as `RENAMED`, and the new OU at the original DN (and anything created in it) as `ONLY_TARGET`.

### 5.5 Targets that hold the source identifiers (`clone -native`, generic LDAP)

A target imported with [`clone -native`](lab.md#importing-with-the-same-objectguid-and-objectsid-clone--native-samba-only), or a generic server cloned with `[mapping] mode = "preserve"` (the default there), has the same identifier (`objectGUID`, `entryUUID`) as the source, so objects are matched by the identifier itself.
`diff` switches to this automatically when the identifier of the first object it compares under `base_dn` (found with the configured filters, so built-in and filtered-out objects never decide; `base_dn` itself when nothing is under it) is the same on both sides, whatever the mode.
It does not switch on the domain GUID alone (a lab filled by `clone` over LDAP can share the domain GUID while object GUIDs differ).
The summary shows `rename/move check: on (objectGUID preserved ...)`.

### 6. When matching is off

With `[mapping] mode = "off"`, or `mode = "file"` with a missing file or one of another source, `RENAMED` / `REPLACED` / `UNMARKED` are not reported.
A renamed or moved object looks like two entries: `ONLY_SOURCE` (the old DN) and `ONLY_TARGET` (the new DN).
The summary says `rename/move check: on / off` (with a mapping file that cannot be used, the reason goes to standard error).
Markers of another source and mapping pairs of another target (a recreated lab) match nothing, so **no false detections are produced**.

## Quick reference: what happened on the target -> diff output

| What happened on the target | diff output |
|---|---|
| An attribute value was changed | `DIFF` (`source:` / `target:` and a wavy line) |
| An attribute was added (the source did not have it) | `DIFF` (`source: (none)`) |
| An attribute was removed | `DIFF` (`target: (none)`) |
| Only letter case was changed | `DIFF` (`case only`) |
| A value of a multi-valued attribute was added or removed | `DIFF` (`only in source` / `only in target`) |
| An object was deleted | `ONLY_SOURCE` |
| An object was newly created | `ONLY_TARGET` |
| The RDN was changed (rename) | `RENAMED` (`renamed`) (*) |
| Moved to a different parent (including outside the starting point) | `RENAMED` (`moved`) (*) |
| Renamed and an attribute was changed too | `RENAMED` and a `DIFF` under the current DN (*) |
| An OU was moved or renamed with its contents | Only `RENAMED` for the OU (the contents are only counted) (*) |
| Deleted and recreated at the same DN | `UNMARKED` with markers, `REPLACED` with identifiers (and a `DIFF` if attributes differ) (*) |
| Moved, and an object with the same name was created at the original DN | `RENAMED` for the original and `ONLY_TARGET` for the new one (*) |
| A password was changed | Not detected (not compared) |
| A masked attribute was changed | Not detected (because it is masked) |
| An attribute not in the allow list was changed | Not detected (add it with `extra_include` to detect it) |

(*) Requires object matching (on by default). With `[mapping] mode = "off"`, a rename or move looks like two entries, `ONLY_SOURCE` + `ONLY_TARGET`, and a recreated object is only compared by its attributes.

## How to read the summary

The scope and counts show what "no differences" is based on.

```

compared objects : ou=5 group=2 user=6
differences:
  ONLY_SOURCE : 1   (only in source: not cloned yet)
  ONLY_TARGET : 1   (only in target: not in source)
  DIFF        : 3   (in both, but attribute values differ)
                    of which case only: 1
  RENAMED     : 2   (same object, but its DN differs on target: renamed/moved)
  UNMARKED    : 1   (same DN, no marker: recreated, or added to the source after the clone)
                    not listed: 12 entries moved along with a renamed/moved parent OU
rename/move check: on (markers in adminDisplayName)
not compared (matches no kind, so clone does not copy it): 123
  msFVE-RecoveryInformation  120
  serviceConnectionPoint       3
compared attributes:
  ou   : objectClass, cn, ou, description
  group: objectClass, cn, sAMAccountName, member
  user : objectClass, cn, sAMAccountName, title, department
not compared:
  masked (config [mask]):
    mail
  excluded (config exclude):
    telephoneNumber
  credentials (clone never copies them):
    unicodePwd
    dBCSPwd
    ntPwdHistory
    lmPwdHistory
    supplementalCredentials
    ms-Mcs-AdmPwd
    ms-Mcs-AdmPwdExpirationTime
    msLAPS-Password
    msLAPS-EncryptedPassword
    msLAPS-EncryptedPasswordHistory
    msLAPS-EncryptedDSRMPassword
    msLAPS-EncryptedDSRMPasswordHistory
    msLAPS-PasswordExpirationTime
    msDS-KeyCredentialLink
    msDS-AllowedToActOnBehalfOfOtherIdentity
    msDS-ManagedPassword
  and any attribute not listed above
```

- `compared objects`: objects compared, per type.
- `RENAMED` / `REPLACED` / `UNMARKED` appear only when objects are matched (`rename/move check: on`; `REPLACED` and `UNMARKED` only when there are any). `not listed` is the number of entries left out because they merely moved along with their parent OU. A line saying objects were found more than once means a marker (or, on OpenLDAP, an `entryUUID`) was copied onto another object; the first one found was used.
- `compared attributes`: the attributes that were compared (excluding masked ones). `not compared`: what was not compared (masked, `exclude`d, the credentials, and attributes not in the allow list).

## JSON output (`-format json`)

For a test program that checks the result, `-format json` writes [JSON Lines](https://jsonlines.org/): one JSON
object per line, a line per difference as it is found, then one summary line. Standard output holds nothing else
(password prompts and warnings go to standard error), the exit codes are the same, and values are never cut short
(`-max-values` applies to the text output only).

```json
{"kind":"DIFF","dn":"CN=Eng,OU=Groups,OU=IDM,DC=example,DC=com","attr":"member","only_source":["CN=Bob,OU=Users,OU=IDM,DC=example,DC=com"],"only_target":[]}
{"kind":"DIFF","dn":"CN=Alice,OU=Users,OU=IDM,DC=example,DC=com","attr":"department","source":["Sales Dept"],"target":["Sales Div"]}
{"kind":"RENAMED","dn":"CN=Cid,OU=Users,OU=IDM,DC=example,DC=com","target_dn":"CN=Cid Renamed,OU=Users,OU=IDM,DC=example,DC=com","renamed":true}
{"kind":"ONLY_SOURCE","dn":"CN=Dave,OU=Users,OU=IDM,DC=example,DC=com"}
{"kind":"SUMMARY","version":1,"compared":{"group":40,"ou":12,"user":1150},"differences":{"DIFF":2,"ONLY_SOURCE":1,"ONLY_TARGET":0,"RENAMED":1,"REPLACED":0,"UNMARKED":0},"case_only":0,"rename_check":"markers in adminDisplayName","implied":0,"duplicates":0,"referenced":3,"not_cloned":{"msFVE-RecoveryInformation":12},"references_not_compared":{"member":2},"compared_attributes":{"group":["objectClass","cn","sAMAccountName","member"],"...":[]},"masked":["mail"],"excluded":[],"credentials":["unicodePwd","..."]}
```

| Field | On | Meaning |
|---|---|---|
| `kind` | every line | `DIFF`, `ONLY_SOURCE`, `ONLY_TARGET`, `RENAMED`, `REPLACED`, `UNMARKED`, or `SUMMARY` on the last line |
| `dn` | differences | The source DN; for a `DIFF` of a renamed object, its DN on the target (as in the text output) |
| `attr` | `DIFF` | The attribute |
| `source`, `target` | `DIFF` of a single-valued attribute | The value on each side, as a list (`[]` when that side has none) |
| `only_source`, `only_target` | `DIFF` of a multi-valued attribute | The values only that side holds (`[]` when none); for `member`, the members removed and added on the target |
| `case_only` | `DIFF` | `true` when the values differ only in letter case |
| `base64` | `DIFF` | `true` when a value is not UTF-8 (a binary attribute): every value of that line is then base64 |
| `target_dn`, `renamed`, `moved` | `RENAMED` | The DN on the target, and whether the RDN changed and whether the parent did |
| `version` | `SUMMARY` | The format version (1). It changes when a field changes meaning or goes away; new fields may be added without it |

The other `SUMMARY` fields are the [summary](#how-to-read-the-summary) as data: `compared` and `differences` per
kind (every kind present, `0` included), `not_cloned` per object class, `references_not_compared` per attribute,
`compared_attributes` per kind, and `masked`, `excluded` and `credentials`. `rename_check` is empty when
renames are not detected. Fields of a line that do not apply are left out, so read them as optional.

A program reads it line by line, for example with `jq`:

```sh
ldap-cronin diff -format json | jq -c 'select(.kind == "DIFF" and .attr == "member") | {dn, removed: .only_source, added: .only_target}'
```

## References that point to renamed objects

AD rewrites references to a renamed or moved object (`member`, `manager`, `managedBy` ...) to the new DN. So **reference attributes are compared after all objects are matched, with the target's new DNs translated back to the source DNs.** References that merely followed a rename are not reported; really added or removed ones still are.

## How rename and move detection works, and its configuration

`diff` must know which source object each target object was cloned from. The target carries that fact itself, in one of two ways, chosen by `[mapping] mode`:

```toml
[mapping]
# mode = "auto"                  # auto | preserve | marker | file | off
# attribute = "adminDisplayName" # marker: the attribute that holds it (default: the profile's)
# operational = true             # preserve: also copy createTimestamp, modifyTimestamp, creatorsName, modifiersName
# file = "mapping"               # file: the local mapping file
```

| Mode | How | Default for |
|---|---|---|
| `preserve` | `clone` creates every object with the source's identifier (`entryUUID`) through the **relax control**, so the target's identifier *is* the source's. Also copies `createTimestamp`, `modifyTimestamp`, `creatorsName` and `modifiersName` at creation (`operational = false` to skip), so the clone looks like production | `ldap` (OpenLDAP) |
| `marker` | `clone` writes `ldap-cronin:<source root>:<source identifier>` into an attribute of every object it creates or updates | `ad` (attribute `adminDisplayName`) |
| `file` | `clone` records the pairs of identifiers in a local file (the fallback for servers that allow neither) | — |
| `off` | No matching | — |

`auto` resolves to `marker` when `attribute` is set, otherwise to the profile's default.

**preserve (OpenLDAP).** The relax control needs `manage` access to the entries, or the rootdn. If the target refuses it, `clone` stops with the remedy instead of creating objects with new identifiers (a target that looks like production but is not). OpenLDAP does not advertise the control and does not refuse a duplicate `entryUUID`. `entryCSN` cannot be set and keeps the clone time; an entry modified after its creation (references applied later, the memberof overlay updating a member) gets the clone time as `modifyTimestamp`. The operational attributes are never compared. `memberOf` is not copied (the overlay derives it from `member`), nor password-policy state such as `pwdChangedTime` (the password is the fixed one).

**marker (AD, Samba over LDAP).** AD and Samba refuse a client-set `objectGUID` over LDAP, so the source key goes into an attribute. The default `adminDisplayName` is allowed on every object class (`top`), single-valued, and used by no product we know of. Another attribute can be named with `attribute` (on a generic server with an extended schema too); before writing, `clone` refuses one that is in an allow list, masked or managed by the server, and on AD one that is not a single-valued string of at least 53 characters. It warns when the attribute is not indexed (`searchFlags` bit 1): every search for a moved object then reads the naming context. The lab image indexes `adminDisplayName`; on a real AD, set it ([active-directory.md](active-directory.md#when-the-target-is-a-real-ad)). Notes:
- The marker names the source by its root identifier, so a marker from another source is ignored, and a dry-run LDIF loaded with `ldapmodify` carries markers too.
- An object at the source DN without a marker is searched for once elsewhere; if the cloned one is found, the object at the DN is `ONLY_TARGET` and the original `RENAMED`, otherwise it is `UNMARKED`. Parents created by `clone` get a marker; ones that already existed on the target (`CN=Users`) are left untouched and matched by DN.
- When a parent OU moved, a child is first looked for at the same RDN under the parent's new DN, so an OU move costs no searches.
- Running `clone` again puts back a marker the program under test removed.
- What is not yet verified on a real AD is listed in [active-directory.md](active-directory.md#limitations).

**file.**
- **The mapping file is a ledger**: it holds every pair of identifiers `clone` ever recorded, and a source object cloned again (because the program under test deleted it, or into another target) gets a second pair instead of replacing the first. A target object is the source's when its identifier is any recorded one. Identifiers are never reused, so this is exact: a restore, or another instance restored from the same snapshot, brings back an identifier recorded earlier, while an object recreated by the program under test has one never recorded and is still `REPLACED`. **Restores, other instances and a recreated lab need nothing**; one file serves every target cloned from one source.
- It consists of **fixed-length records** (66 bytes, one pair each) sorted by source then target identifier. `diff` **binary-searches the file** instead of loading it (constant memory; about 20 reads for a million entries), so an object with one pair costs one lookup; each further pair is the next record.
- `clone` appends new pairs to a separate file and, at the end, rewrites the file after an external sort. A pair already recorded is not added again, so re-runs do not grow the file. The pairs from a `clone` that was interrupted are picked up by the next `clone`.
- **One `clone` at a time**: `clone` holds `<file>.lock` while it runs, and a second one (into another instance) stops with the holder's PID. A lock left by a killed process is deleted by hand. `diff` only reads and takes no lock.
- The header records the format version, the identifier attribute and **the identifier of the source's naming-context root**, not the URL; a file of another source is rejected, detection is off, and the reason goes to standard error.
- `clone` reads the target identifier once per newly created object (the response to an add does not contain it). Only `clone` records the mapping; `-dry-run` does not. A moved object cloned more than once is searched for with one OR filter.

- **Re-running clone does not follow renames on the source side** (it only adds, and does not handle deletions). This feature exists so that `diff` can verify changes made on the target.

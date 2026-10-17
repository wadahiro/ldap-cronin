<!-- Output and comparison rules of ldap-cronin diff. Referenced from README.md. -->

# diff output and comparison rules

`diff` compares the source (the clone origin) with the target and finds **changes made on the target after the clone**.
It is read-only.

```sh
./bin/ldap-cronin diff -config config.toml            # exit code 1 if there are differences
./bin/ldap-cronin diff -config config.toml -max-values 0   # show all values of multi-valued differences
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
- For DN reference attributes (`member`, `manager` and so on), references outside the scope (built-in objects and the like) are removed from both sides before comparing.
- The objects compared are those that match `[scope] objects` and `[scope.filters]`.
- Use the same configuration file for clone and diff; different settings change the result (an `exclude` added only for diff hides that attribute).

## Kinds of output

| Kind | Meaning | `[mapping] file` |
|---|---|---|
| `ONLY_SOURCE` | Only in the source, not on the target (not cloned yet, or deleted on the target) | Not needed |
| `ONLY_TARGET` | Only on the target, not in the source (newly created on the target) | Not needed |
| `DIFF` | Present on both sides, but attribute values differ | Not needed |
| `RENAMED` | The same object has a different DN on the target (renamed or moved) | Required |
| `REPLACED` | A different object than the cloned one exists at the same DN, and the original is nowhere to be found | Required |

`RENAMED` and `REPLACED` are decided from the mapping (`[mapping] file`); without it, see [when the mapping is missing or stale](#6-when-the-mapping-is-missing-or-stale).

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

At most 10 values are shown per direction, and the rest is shown as `... (+N more; ...)`. `-max-values <n>` changes the limit (`0` shows all). Example with `-max-values 2`:

```
DIFF        CN=Eng,OU=Groups,OU=IDM,DC=example,DC=com
            member:
              only in target (5):
                - CN=User1,OU=Users,OU=IDM,DC=example,DC=com
                - CN=User2,OU=Users,OU=IDM,DC=example,DC=com
                ... (+3 more; use -max-values to show more)
```

**1-5. DN reference attributes** (`member`, `manager`, `managedBy`, and anything added through `extra_include` such as `seeAlso`; detected automatically from the source schema):
DN case and escaping (`\,` versus `\2C`) differences are not reported; out-of-scope DNs are removed from both sides first.

### 2. Presence of objects (`ONLY_SOURCE` / `ONLY_TARGET`)

Deleted on the target: `ONLY_SOURCE`; newly created: `ONLY_TARGET`.

```
ONLY_SOURCE CN=Dave,OU=Users,OU=IDM,DC=example,DC=com
ONLY_TARGET CN=Newcomer,OU=Users,OU=IDM,DC=example,DC=com
```

The same applies under a moved OU: a child deleted after the move is `ONLY_SOURCE`, a new one is `ONLY_TARGET`.

### 3. Rename and move (`RENAMED`; requires `[mapping] file`)

The DN of an object was changed on the target; the unchanged identifier (`objectGUID`, or `entryUUID` on a generic server) identifies it via the mapping.
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

Even with the same DN, an object whose `objectGUID` differs from the one recorded by clone is treated as a different object.

**5-1. Deleted and recreated at the same DN** (the original is nowhere to be found): `REPLACED`.
**Attributes are still compared, to see how the different object differs from the source values** (a `DIFF` follows if there are differences; if they are identical, only `REPLACED` is shown).

```
REPLACED    CN=Eve,OU=Users,OU=IDM,DC=example,DC=com
            same DN, but a different object than the one that was cloned (the original is gone)
DIFF        CN=Eve,OU=Users,OU=IDM,DC=example,DC=com
            description:
              source: (none)
              target: recreated by another program
```

**5-2. An OU with the same name was recreated after the OU was moved**: the original OU is still alive elsewhere, so it is not called `REPLACED`.
Instead the original OU is shown as `RENAMED`, and the new OU at the original DN (and anything created in it) as `ONLY_TARGET`.

### 5.5 Targets imported with `clone -native` (no mapping needed)

A target imported with [`clone -native`](lab.md#importing-with-the-same-objectguid-and-objectsid-clone--native-samba-only) has the same `objectGUID` as the source, so the same detection (`RENAMED` / `REPLACED`) as in 3 to 5 above works without the mapping (`[mapping] file`).
`diff` switches automatically when the `objectGUID` of the first object it compares under `base_dn` (found with the configured filters, so built-in and filtered-out objects never decide; `base_dn` itself when nothing is under it) is the same on both sides.
It does not switch on the domain GUID alone (a lab filled by `clone` over LDAP can share the domain GUID while object GUIDs differ).
The summary shows `rename/move check: on (objectGUID preserved ...)`.

### 6. When the mapping is missing or stale

If `[mapping] file` is not set, the file does not exist, or it belongs to a different source or target, `RENAMED` / `REPLACED` are not detected and **the behavior is the same as before**.
A renamed or moved object looks like two entries: `ONLY_SOURCE` (the old DN) and `ONLY_TARGET` (the new DN).
Whether a mapping exists and in what state is shown in the summary as `rename/move check: on / off` (when it is missing or does not match, the reason goes to standard error).
A stale mapping (target recreated, identifiers changed) cannot be looked up, so **no false detections are produced**.

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
| Deleted and recreated at the same DN | `REPLACED` (and a `DIFF` if attributes differ) (*) |
| Moved, and an object with the same name was created at the original DN | `RENAMED` for the original and `ONLY_TARGET` for the new one (*) |
| A password was changed | Not detected (not compared) |
| A masked attribute was changed | Not detected (because it is masked) |
| An attribute not in the allow list was changed | Not detected (add it with `extra_include` to detect it) |

(*) Requires `[mapping] file`. Without it, a rename or move looks like two entries, `ONLY_SOURCE` + `ONLY_TARGET`, and `REPLACED` becomes an attribute comparison (identifiers cannot be compared).

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
  REPLACED    : 1   (same DN, but a different object than the one cloned)
                    not listed: 12 entries moved along with a renamed/moved parent OU
rename/move check: on (14 objectGUID pairs in the mapping file)
compared attributes:
  ou   : objectClass, cn, ou, description
  group: objectClass, cn, sAMAccountName, member
  user : objectClass, cn, sAMAccountName, title, department
not compared:
  masked (config [mask])        : mail
  excluded (config exclude)     : telephoneNumber
  never compared                : password attributes (unicodePwd, dBCSPwd, ntPwdHistory, lmPwdHistory, supplementalCredentials),
                                  and any attribute not listed above
```

- `compared objects`: objects compared, per type.
- `RENAMED` / `REPLACED` appear only when the mapping is in use (`rename/move check: on`). `not listed` is the number of entries left out because they merely moved along with their parent OU.
- `compared attributes`: the attributes that were compared (excluding masked ones). `not compared`: what was not compared (masked, `exclude`d, password-related, and attributes not in the allow list).

## References that point to renamed objects

AD rewrites references to a renamed or moved object (`member`, `manager`, `managedBy` ...) to the new DN. So **reference attributes are compared after all objects are matched, with the target's new DNs translated back to the source DNs.** References that merely followed a rename are not reported; really added or removed ones still are.

## How rename and move detection works, and its configuration

When `[mapping] file` is set, `clone` records the correspondence between source and target identifiers (`objectGUID` on AD, `entryUUID` on a generic server) and `diff` uses it.
The identifier is assigned by the target and cannot be copied, so **the mapping is kept in a local file** (nothing is added to the target).

```toml
[mapping]
file = "mapping"
```

- **The mapping file** consists of **fixed-length records** (66 bytes each) sorted by source identifier. `diff` **binary-searches the file** instead of loading it (constant memory; about 20 reads for a million entries), and only for entries whose DN was not found on the target.
- `clone` appends new pairs to a separate file and, at the end, rewrites the file after an external sort (sorting chunk by chunk and merging). The pairs from a `clone` that was interrupted are picked up by the next `clone`.
- Only identifiers are stored, no DNs or names. The header records the format version, the identifier attribute and **the identifiers of the source and target naming-context roots** (plus `base_dn`), not the URL: it survives a host or port change (a lab restored on another port) but a different directory (a recreated target) is rejected, detection is off, and the reason goes to standard error. A file written by an earlier version of the tool is refused the same way; run `clone` again to record a new one.
  It can be kept in a snapshot together with the data ([docs/lab.md](lab.md)).
- The load of `clone` increases by exactly one read of the target identifier per newly created object (because the response to an add does not contain it).
- Only `clone` records the mapping; `-dry-run` does not.
- **Re-running clone does not follow renames on the source side** (it only adds, and does not handle deletions). This feature exists so that `diff` can verify changes made on the target.

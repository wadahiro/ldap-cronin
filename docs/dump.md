# Dumps: read production once, clone from the file

`ldap-cronin dump` reads a source, read only, into one LDIF file. Set it as `[source] ldif` and `clone`, `diff`,
`check`, `schema`, `clone -native` and `lab up --like-source` read the file instead of the server:

- production is connected once, at a time chosen for it, with an account that can only read;
- every clone and diff after that is of the same moment of production, and never touches it;
- the file can be taken on production's side and carried to where the clones are made, and looked through first.

```sh
export LDAP_CRONIN_SOURCE_PASSWORD='...'          # or asked
ldap-cronin dump -url ldaps://dc01.example.com:636 -bind-dn 'CN=svc-read,OU=Svc,DC=example,DC=com' \
  -base-dn 'OU=IDM,DC=example,DC=com' -o prod.ldif.gz [-mask mail,telephoneNumber]
```

```toml
[source]
ldif = "prod.ldif.gz"        # instead of url, bind_dn and the connection settings; no password is asked
```

`dump` reads no config file: what it needs is on its command line, so it runs on production's side with the binary
alone. `-ca-file`, `-insecure-skip-verify`, `-start-tls` and `-timeout` are those of `[source]`.

## What is in it

- The root DSE (the server type, the naming contexts).
- The schema: on AD the `attributeSchema` and `classSchema` entries, on a generic server the subschema entry.
- On AD, the `crossRef` entries of the configuration partition (the NetBIOS name).
- The root of the naming context, the entries between it and `-base-dn`, and every entry under `-base-dn`, of
  every kind: `[scope] objects` and `filters` narrow what is cloned at the time of the clone.
- The entries outside `-base-dn` that a DN-valued attribute names (a member, a manager), including those of the
  configuration partition, and the entries above them; not what they name in turn, as `clone` does not follow it.
- The operational attributes the tool reads by name (on a generic server `entryUUID` and the creation metadata).

Never in it: the credentials the profile names (password hashes, LAPS passwords, BitLocker and gMSA secrets, ...),
whatever the bind account may read. The header lists them.

`[scope] base_dn` of a clone from a dump must be its `-base-dn` or below it.

## The file

An LDIF file of content records (`ldapsearch` writes the same), compressed when its name ends in `.gz`. Comment
lines say what it is; LDIF tools skip them:

```
# ldap-cronin dump
# version: ...
# dumped-at: 2026-10-21T09:12:33Z
# server: ldaps://dc01.example.com:636
# profile: ad
# base-dn: OU=IDM,DC=example,DC=com
# root-dn: DC=example,DC=com
# masked (value: ********):
#   mail
# excluded (credentials, never dumped):
#   dBCSPwd
#   ...
# referenced: the entries outside base-dn a reference names, and their parents, without what they name
#
# section: root-dse
...
# end: 5123 entries (root-dse 1, schema 1530, configuration 3, base 3502, referenced 87)
```

- It is written to a temporary file next to `-o` and renamed when complete. A file without the `# end:` line, or
  with another number of entries, is refused: a dump cut off would clone some users and members and not others.
- `clone` and `diff` say which dump they read, of which server and when: diff compares the target with that moment.
- `-mask` masks attributes in the file itself, so it holds none of their values (they cannot be unmasked later). The
  same rules as `[mask]` apply: an attribute holding DNs or identifying an object cannot be masked.
- The file holds everything else of the entries, personal data included: keep it as you keep production's data
  (it is written readable by its owner only).

## Reading it

- **Filters**: the kinds' filters, `[scope] filters` and the tool's own are evaluated as the server does for `&`, `|`,
  `!`, equality, presence, substrings, ordering (`>=`, `<=`) and AD's bitwise matching rules
  (`(userAccountControl:1.2.840.113556.1.4.803:=2)`, every bit set, and `.804`, any of them).
  - `objectCategory=person` matches the class's `defaultObjectCategory`, as on AD (from the dump's schema; without
    the class there, the category named after it, `CN=Person`).
  - A DN compares as a DN, a binary value byte for byte, the rest ignoring case.
  - Ordering compares integers (`uSNChanged`, `pwdLastSet`) as numbers and the rest as text, which orders
    generalized times of the same form (`whenChanged>=20260101000000.0Z`) by time.
  - Approximate matches (`~=`) and other matching rules (the in-chain rule `1.2.840.113556.1.4.1941`, `:dn`) are
    refused with the filter named, never taken as a match.
- **Memory**: none of the entries is held. A search reads the file from the start, an entry at a time; a read of one
  entry goes straight to it through an index of where each starts (16 bytes an entry: under 2 MB for 100,000). A
  `.gz` dump is expanded to a temporary file first (readable by its owner only, removed when the command ends), as
  a compressed file cannot be read from the middle: plan the disk for it.
- **Ranges**: a large `member` is read in full when dumping (AD and Samba return it in ranges of 1500).

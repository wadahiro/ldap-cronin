# Operational notes (large data, load, memory, performance)

Behavior and load when cloning and comparing a large directory.

## Large data sets

- Searches are paged, 1000 entries at a time (matching the AD MaxPageSize). There is no upper limit on the number of users or groups.
- For a group's `member`, AD splits a group with many values into ranges such as `member;range=0-1499`.
  Samba4 does not split automatically and returns everything, so **the tool always requests an explicit range (1500 values at a time)**
  and fetches the rest with `member;range=N-*`, then joins the pieces. AD and Samba therefore go through the same path.
- Adding members on the target is split into modify operations of 500 values each.

## Load on the source AD

The tool **only reads from the source: it never writes, and it never issues a query per entry**. It runs paged searches of 1000 entries one after another over a single connection and does not read in parallel (what is parallelized is the work against the target).

- Number of searches (subtree searches under `base_dn`): **at most 8 for clone, 5 for diff**. To keep memory low, the tool does not hold all entries and re-reads instead.
  clone: 3 for planning (ou with all attributes, group and user with the DN only) + 2 for applying (group and user, all attributes) + 3 for applying references (only entries that have references).
  diff: 3 for planning + 2 for comparing (group and user, all attributes).
- Other reads: the root DSE and the schema (to detect DN reference attributes, a few hundred entries), reading parent containers (a few entries), and range retrieval for groups with more than 1500 members.
- A slow target keeps the source search open longer (reading and writing are interleaved).
- The source is not searched in parallel, to keep its load down.
- To read production once and never during a clone, take a dump (`ldap-cronin dump`, [dump.md](dump.md)): the
  clones and diffs that follow read the file. A dump is a subtree search under `base_dn`, one for the schema, and a
  read per entry outside `base_dn` that a reference names. Reading it holds none of the entries in memory, only an
  index of where each starts (under 2 MB for 100,000 entries); a `.gz` dump is expanded to a temporary file first.

## Load on the target AD (clone)

The operations against the target per user are as follows (the counts are guaranteed by `internal/clone/ops_test.go`).

| Situation | Operations |
|---|---|
| New user (first run) | AD: **3**: add (disabled), set password, finalize UAC. Generic LDAP: **1**: the add carries the password. With `[mapping] mode = "file"`, one extra read of the target identifier. Markers and preserved identifiers ride in the same add |
| Existing, unchanged user (re-run) | **2**: add (rejected), then one read. No writes |
| New group | 1 add + member additions (1 per 500 values) |

- The target is assumed to be empty, so the tool tries the add first and reads only when the entry already exists, then updates only the attributes that differ (it does not read first against an empty target).
- The main cost is **setting the password**. It involves a password hash computation; on Samba it takes about 37 ms per user, and writes are serialized on the server (more connections do not make it faster).
- Applying writes data and is replicated to the other DCs. Run it against a test target, outside business hours.

## Memory usage

Memory does not grow in proportion to the number of entries (`internal/clone/memory_test.go` guarantees that clone and diff of 200,000 users stay within 60 MB).
Measured: about 10 MB for 200,000 users (holding every entry took about 660 MB).

- Searches are processed one page (1000 entries) at a time, and the reading side waits when writing is slow. The number of entries in flight never exceeds `workers`.
- Only a hash set of the target DNs (8 bytes per entry; a few tens of MB even for a million entries) and the OU and parent container entries stay resident.
- `member` / `manager` / `managedBy` are not carried along at creation time; they are applied by re-reading the source once all objects exist.
- `diff` does not accumulate differences; it prints them as soon as it finds them (memory does not grow even when the target is empty and everything differs). The exception is DN reference attributes whose values differ: they are judged after every object is matched (a rename on the target rewrites references to it), so their values are kept until then. That grows with the number of differing reference values, not with the size of the directory.
- Only the first 1000 warnings are shown and kept; the rest are only counted.
- Two things are bounded: the number of OUs and parent containers (a few KB each) and the number of members in a single group (the DNs of that group are held temporarily).

## How long a run takes

`clone` and `diff` count what they will go through before they start (a search of DNs only), so their progress
(see the [README](../README.md#usage)) gives every phase a total: the OUs and parents, each kind, then the
references (`clone` counts the entries holding one with one more search of DNs). The time left is the phase's own,
at the rate it has had so far, and appears after two seconds of it. Phases go at different rates: parents and
groups are few, users are the bulk, and the reference pass costs one modify per 500 members, so a large group
holds it up. For a first estimate of a whole run, use the [figures below](#performance-figures-measured-with-samba4-as-the-target)
or a dry-run, which goes through the same phases without writing.

## Stopping a run and hung servers

- **Ctrl-C** (or SIGTERM) stops `clone` and `diff` at their next LDAP operation; what is already sent finishes. A mapping file (`mode = "file"`) is still written, and a re-run continues where `clone` stopped (it is idempotent; from a dump it skips what is done, [below](#resuming-a-clone-from-a-dump)). An interrupted `diff` prints no summary, since a partial comparison would read as "no differences" in the part it did not reach. A second Ctrl-C ends the process at once. The exit code is 2.
- **Busy** (LDAP result 51) or **Unavailable** (52) from the target is retried with growing pauses, about half a minute in all, before the run stops. Windows answers Busy (`problem 5001 (BUSY), data -1102`, a write conflict) when the writes of parallel workers touch the same record, and the retry goes through.
- **`timeout`** in `[source]` / `[target]` (default `2m`, `"0"` for none) bounds every LDAP operation, so a server that stops answering fails the run instead of blocking it. It is generous because one modify of a large group on Samba can take seconds.

### Resuming a clone from a dump

A clone over LDAP from a dump (`[source] ldif`) records each object it finished, and each entry whose references
it wrote, in a journal: the file `[run] journal`, by default the config file's path with `.journal` appended
(`lab.toml.journal`). A run after an interrupted one (Ctrl-C, a lost session, an error, `-time-limit`) says
`resuming: the journal ... holds N objects ...` and skips them without reading the target, so it goes on where the
other stopped instead of comparing every object again. A complete run removes the journal, and the one after it
compares everything.

- The journal is valid for the same dump and the same config (but `[run]`: another number of workers goes on), and
  the same target: it records the target's domain `objectGUID` and, as it goes, the root DSE's
  `highestCommittedUSN`. A target made anew (another GUID), or restored to an earlier point (`lab restore`: a
  smaller USN), drops it, as do another dump and another config: `note: the journal ... is dropped, and every
  object is compared`.
- From a server there is no journal (it may change between runs): the next run compares every object again. Nor
  on a target that says neither (generic LDAP).
- Done means done for the target: do not write the cloned objects between an interrupted run and the next (a test
  run, a hand edit), or remove the journal first, as the next run does not compare what it records.
- The last object an interrupted run started may be half done: it is not in the journal, and the next run
  completes it. An entry not added (its name taken on the target) is never journaled, so the next run leaves it out
  again, with the values naming it.
- The journal holds the DNs of the cloned objects; it is written with the permissions 0600, as the mapping file is.

## Performance figures (measured with Samba4 as the target)

Cloning 400 users (measured with different `workers` values):

| workers | Clone | Read-only re-run |
|---|---|---|
| 1 | 19.5 s | 3.5 s |
| 4 | 16.7 s | 1.6 s |
| 8 | 17.4 s | 1.7 s |
| 16 | 18.1 s | 1.8 s |

- **Reads (diff, and the difference check on a re-run) get faster with parallelism**, but **writes to Samba hardly get faster**.
  Plain `ldapmodify` with 1 and 8 connections is the same (120 password settings: 4.49 s / 4.55 s): Samba serializes writes with a database lock.
- Time goes mostly to setting passwords. Rule of thumb: **about 45 ms per user** (about 8 minutes for 10,000 users, about 75 minutes for 100,000 users).
- These figures were measured before the lab stopped fsyncing its databases (`ldb:nosync`, [lab.md](lab.md#starting-a-docker-lab-by-hand-lab-up)); since then the E2E's 1,600 users clone in about 19 s (about 12 ms per user) where they took 25 to 70 s. A real AD fsyncs: use the figures above for it.
- The effect of parallelism against a real AD has not been measured. Please try different `workers` values.
  For measurements you can run `go test -tags e2e -run Bulk -v ./e2e/` with `E2E_BULK_USERS` / `E2E_WORKERS` set (after `docker compose --profile e2e up -d`).

# AGENTS.md

ldap-cronin (LDAP cRONIN): a Go CLI that clones OUs, groups and users between LDAP directories (AD, Samba AD, generic LDAP) and verifies what changed on the target. Layout and design decisions: `docs/DEVELOPMENT.md`.

## Commands

- `make check` — format, vet, tidy, unit tests (`-race`) and build. Run before finishing any change.
- `make e2e` — E2E against real servers; needs docker and takes about 6 minutes. Run it when touching `internal/lab`, `ldapdir`, `clone`, `diff`, `profile`, `identity`, `plan` or `app`.
- `make fmt` — gofmt.

## Conventions

- Everything is English: code, comments, messages, docs, commit messages.
- Commits follow Conventional Commits (`feat:`, `fix:`, `docs:` ...); the body says why.
- Comments explain why, and why an alternative was rejected. Do not narrate what the code does.
- No hard-coded values that belong in config. Do not add dependencies without a reason.
- Passwords never go into config files, command-line arguments or logs; pass them through the environment (`-e NAME`) or prompt for them.
- Server-type differences belong in `internal/profile`, not in `if` branches on a server name.

## Gotchas

- Unit tests use `internal/fakedir`; keep it behaving like a real server (it rejects missing parents and dangling references).
- `lab` and `clone -native` are AD/Samba only. Native import uses unsupported Samba internals (tested on 4.19.5); keep that stated wherever it is documented.
- Change docs together with behavior: `README.md` stays short, details live in `docs/`. Keep relative links and anchors valid.

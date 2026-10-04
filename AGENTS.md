# AGENTS.md - steward-authz

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

Access-rule engine and permission catalog shared by Steward services: a Go library with no I/O,
imported by every service that decides access in-process, plus the Rego bundles in `policies/`.

- Every decision fails closed: default deny, first match wins. Never add a path that allows by
  default.
- The catalog and role table are snapshot-tested. Change them only on purpose, with the snapshot.

## Using steward-authz

- `Compile(chain)` / `Resolve` for the category rules (target category first, then ancestors);
  `Acknowledgement` for the ungated acknowledge decision.
- `Authorize` and `HasCapability` for one catalog permission.
- `Entries()` goes into the service's go-apperr registry; errors match the `Err*` sentinels.
- See `docs/access-model.md` and `docs/catalog.md`.

## Layout

- `catalog.go` - permissions, roles, the role matrix
- `authorize.go` - `Subject`, `Resource`, `Authorize`, `HasCapability`
- `rules.go`, `resolve.go` - category rules and the rule engine
- `errors.go` - codes and go-apperr entries
- `policies/` - Rego v1 packages and their tests
- `scripts/publish-bundle.sh` - bundle upload, with `publish-bundle_test.sh`

## Build, test, lint

- Build: `task build`
- Test: `task test`; Rego: `task rego:test` (needs OPA 1.x)
- Lint: `task lint`
- License headers: `task license`
- Until go-apperr v1.2.0 is released, build through a git-ignored `go.work` that uses its branch
  checkout (and `apperrgrpc/`); never a `replace` directive or a pseudo-version.

## Logging

Follow the logging rules in `CLAUDE.md`. In short:

- Log generously: entry and exit of significant operations, decisions and branches, retries, state
  changes, external calls (target, duration, outcome), and every error with its context.
- Levels: `trace` for step-by-step detail, `debug` for flow, `info` for lifecycle, `warn` and
  `error` for problems. The environment filters the volume, so err on the side of too much.
- Environments: local dev `trace` with `LOG_FORMAT=console` (never JSON), dev cluster `debug`,
  qa/staging `info`, production `error`. Every cluster environment logs JSON. Set levels through
  `LOG_LEVEL` and `LOG_FORMAT`, never in code; local settings live in the run target or
  `.env.example`.
- Never log secrets, tokens, or personal data, not even at `trace`. Log an opaque or keyed ID.

## Conventions and gotchas

- See `CLAUDE.md` for the branch/commit/PR rules; they are enforced by the git hooks in
  `.claude/hooks` (run `bash .claude/hooks/install.sh` once per clone).
- Open every PR as a draft. CI skips drafts, so run the full checks locally, push once they pass,
  and mark the PR ready when the work is finished; see CLAUDE.md "CI and Actions minutes".
- The library logs nothing itself; `WithLogger` hands go-authz a `log/slog` logger for debug
  decision lines.
- Rego method names follow each service's proto package; keep them in step with the services.

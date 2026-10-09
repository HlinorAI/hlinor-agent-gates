# Changelog

## 0.4.0 — 2026-10-09

- Added opt-in Linux enforced mode with separate agent, gate and runner OS users, protected bare repositories and restricted push hooks.
- Verification runs committed exports as ag-runner under a machine-wide lock; timeouts kill runner processes and temporary files are cleared as the runner UID.
- OS identities replace --as; verification/merge receipts are gate-signed and Owner acceptance signatures are mandatory.
- Bare merges use commit-tree and atomic ref transactions, binding reviewed refs, policy tree and test command.
- Setup accepts only a protected root-owned kit checkout and imports committed main without reading working-tree filters.
- Protected archive attributes prevent export-ignore/export-subst bypasses; .gitattributes edits appear as test changes.
- Setup denies cron/at scheduling for the runner and removes existing schedules; root doctor checks schedules, linger and archive-attribute integrity.
- Added 14 effect-based attack scenarios, container regressions and an ubuntu-latest enforced CI job. CI results remain to be verified after publication.

## 0.3.1 — 2026-10-09

- Fixed policy classification for installed projects: protect gate files and policy/checklist documents, allow ordinary bin/ and init.sh edits; optional POLICY_PATHS globs extend the protected paths.

- Test runs use isolated process groups and a configurable 1800-second deadline; timeout records exit 124 and REJECT.
- Receipts record changed test files; accept warns about collection and test configuration edits.
- BREAKING: policy changes default to deny and require Owner `--allow-policy-change`; acceptances record the override and merge rechecks it.
- Accept surfaces LARGE_DIFF (more than 1000 changed lines) and LOCKFILE risks.
- Policy/test paths use merge-base diffs, fixing false positives from main-only changes.
- Empty project roots warn explicitly; CI uses actions/checkout@v5.
- Installers share a common-dir flock and clean up their own worktrees/branches on creation failure, retaining the install commit and recovery instructions.
- Added Quickstart, supported-platform statement and threat model. macOS validation remains with CI.

## 0.3.0 — 2026-10-08

- BREAKING: init.sh without --test-cmd now fails closed (was: python3 -m pytest tests -q)

- Added opt-in machine setup, scoped project roots and a post-commit install hook.
- New projects install from defaults on the first clean commit; pending installs retry.
- Existing and cloned repositories are offered installation once, never silently installed.
- Added marked project/global instructions with preservation of surrounding user text.
- Unconfigured test commands fail closed; defaults can be overridden explicitly.
- Added 14 automatic-install scenarios to Linux and macOS CI.

### Known limitations

- Policy warning uses two-dot diff — false positives when main moved.
- setup-global without --root configures no roots silently.

## 0.2.1 — 2026-10-08

- Verification receipts list gate policy files changed by the branch.
- Verify and accept warn about policy changes without denying them.
- Document the trusted main CLI path and add a policy-change regression test.

## 0.2.0 — 2026-10-08

- Added stdlib Python CLI with Bash entry point: verify, accept, merge and status.
- Verification tests the exact merge tree and main baseline in temporary worktrees.
- Canonical receipts, test logs and hashes live in the shared Git common directory.
- Owner acceptances support a 24-hour TTL and optional SSH signatures.
- Merge refuses stale refs, dirty main, tampered or reused receipts and invalid signatures.
- Installer requires Git 2.38 and installs CLI plus configured test/Owner settings.
- Added gate regression tests to both Linux and macOS CI.
- Policy is loaded only from main; accept/merge reject a mismatched test command.
- Signature tests report SKIP when ssh-keygen is unavailable.
- Same-user direct Git remains outside the v0.2 enforcement boundary.

### Known limitations

- A branch can change `.agent-gates/config` and `bin/` in its diff; these changes are surfaced only in the diffstat and require review.
- Run the CLI only from `<main>/.agent-gates/`. A copy in the author's worktree running under the same OS user is not trusted.

## 0.1.1 — 2026-10-08

Fixes from an independent review of 0.1.

- **No overwrites.** Helpers moved to `.agent-gates/` (`config`, `add_agent.sh`, `backup.sh`); install refuses if already installed or if both `NAME.md` and `NAME.agent-gates.md` exist. All checks run before the first change.
- **`backup.sh` worked only from inside the repo**: `git bundle verify` now runs with `-C <repo>`.
- **Locks are write-tested** and reported per path as `LOCKED` / `NOT LOCKED (advisory only)`. New `--require-locks` aborts before any other change if a path can't be locked. Locks are applied first.
- **macOS**: path locks via `chflags uchg`; repo paths resolved with `pwd -P` (`/tmp` and `/var` are symlinks there).
- **Tests**: `tests/test_init.sh` (26 checks) + CI on Linux and macOS.
- README: explicit table of what is machine-enforced vs policy-only.

## 0.1 — 2026-10-08

Initial release.

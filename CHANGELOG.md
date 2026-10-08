# Changelog

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

# Changelog

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

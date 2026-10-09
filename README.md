# hlinor-agent-gates

**Governance for solo developers running several AI coding agents (Claude Code, Codex, Cursor, Gemini, ZCode, Manus…) on one repository.**

Worktree tools give each agent its own folder, but they don't stop an agent from approving its own work, skipping half your tests, or quietly editing files that should never change. This kit adds the missing gates, in about 2 minutes, on top of whatever you already use.

```
Coder ──► Verifier (a different agent) ──► Owner (you) ──► Git Agent merges
  │            re-runs everything              accepts         only after both
  └── works only in its own worktree
```

Supported: Linux, macOS. Not supported: Windows.

## Quickstart (5 minutes)

This creates a temporary demo repository with a real, failing-on-error test command.
The Owner reviews the acceptance summary before the Git Agent merges.
For your own project, use its full test command with `--test-cmd`.

```bash
git clone https://github.com/HlinorAI/hlinor-agent-gates
cd hlinor-agent-gates
REPO="$(mktemp -d)"
git -C "$REPO" init -q -b main
git -C "$REPO" config user.name Demo
git -C "$REPO" config user.email demo@local
printf 'ready\n' > "$REPO/message.txt"
printf '%s\n' 'set -e' 'test "$(cat message.txt)" = ready' 'echo "1 passed"' > "$REPO/check.sh"
git -C "$REPO" add message.txt check.sh
git -C "$REPO" commit -qm initial
./init.sh "$REPO" --agents codex,claude --owner you --test-cmd 'bash check.sh' --dry-run
./init.sh "$REPO" --agents codex,claude --owner you --test-cmd 'bash check.sh'
# Coder works and commits in its own worktree.
printf 'example\n' > "$REPO-wt/codex/example.txt"
git -C "$REPO-wt/codex" add example.txt
git -C "$REPO-wt/codex" commit -qm 'Add example'
# Independent Verifier runs the gate; Owner reads the summary and types yes.
VERIFICATION_ID="$("$REPO/.agent-gates/agent-gates" verify agent/codex --as claude)"
"$REPO/.agent-gates/agent-gates" accept "$VERIFICATION_ID"
# Git Agent uses the id printed after Owner acceptance.
read -r -p 'Accepted receipt ID: ' ACCEPTANCE_ID
"$REPO/.agent-gates/agent-gates" merge "$ACCEPTANCE_ID"
"$REPO/.agent-gates/agent-gates" status agent/codex
```

## What it sets up

| | What | Enforced by |
|---|---|---|
| 1 | One worktree + branch per agent (`<repo>-wt/<name>`, `agent/<name>`) | git |
| 2 | Verifier differs from author; Owner accepts the tested result before merge | `agent-gates verify / accept / merge` |
| 3 | Verifier checklist: re-run the **full** suite, compare test counts, check baseline, hunt fail-open defaults | `VERIFIER.md` |
| 4 | Paths agents must never touch | **OS** (`chattr +i` on Linux, `chflags uchg` on macOS), write-tested, not a prompt |
| 5 | One test command for everyone | `.agent-gates/config` + `GIT_POLICY.md` |
| 6 | No push by agents; verified `git bundle` backups | policy + `.agent-gates/backup.sh` |

## Install

```bash
git clone https://github.com/HlinorAI/hlinor-agent-gates
cd hlinor-agent-gates
./init.sh /path/to/your/repo --agents codex,claude,zcode --owner you --dry-run   # preview
./init.sh /path/to/your/repo --agents codex,claude,zcode --owner you \
  --protect /srv/exports/approved,/srv/sent-mail --require-locks
```

Requirements: git ≥ 2.38, bash, python3. Optional acceptance signing requires SSH signing support in `ssh-keygen`. Path locks: Linux needs root + `chattr` on a filesystem that supports it (ext4, xfs); macOS uses `chflags uchg`.

Every lock is **write-tested** after it is applied, and the summary says `LOCKED` or `NOT LOCKED (advisory only)` per path. With `--require-locks`, a path that can't be locked aborts the install before anything else is written.

`init.sh` checks everything before changing anything. It refuses a dirty working tree (worktrees branch from the last commit, so uncommitted work would be invisible to every agent), refuses to install twice, and preserves your text: its own helpers live in `.agent-gates/`, and if `GIT_POLICY.md` exists it writes `GIT_POLICY.agent-gates.md` for you to merge.

Installers serialize through `flock` at `<git-common-dir>/agent-gates/install.lock`
using Python's stdlib on both supported systems. Dry-run creates no lock file.
If a worktree creation fails, the installer removes its own attempted worktrees
and branches, preserves unrelated work and the installation commit, and prints
recovery commands to create the worktrees after fixing the error.

Then send each agent the message from `AGENT_ONBOARDING.md`. New agent later:

```bash
.agent-gates/add_agent.sh manus
```

## Automatic installation (v0.3)

```bash
./setup-global.sh --root /path/to/projects --agents codex,claude,zcode --dry-run
./setup-global.sh --root /path/to/projects --agents codex,claude,zcode
./setup-global.sh --uninstall
```

Setup copies the kit to `~/.agent-gates/kit`, writes defaults and resolved project
roots, and sets Git's global `init.templateDir`. A foreign template setting is
refused without changes. Existing global instruction files receive a marked
block only when their parent directory exists; surrounding text is preserved.
Uninstall removes the setting and blocks, leaving the kit and projects intact.
An empty effective roots list prints `WARNING: no roots configured, auto-install disabled`.
Re-running without `--root` preserves an existing configured roots list.

The post-commit hook installs new repositories under those roots after their
first clean commit. A dirty tree writes a pending marker and retries after a
clean commit. Existing/cloned repositories are asked in a terminal or notified
once. Linked worktrees and already installed projects are skipped. Hooks can be
removed by the same user; this is a setup convenience, not a security boundary.

`init.sh <repo> --from-defaults` reads `AGENTS`, `OWNER_NAME`, and `TEST_CMD` from
`~/.agent-gates/defaults`; explicit flags override them. Without a test command,
verification is REJECT until the Owner sets a real command in main's config.
Installation commits marked blocks in `AGENTS.md`, `CLAUDE.md`, and `GEMINI.md`;
unknown agents use `add_agent.sh <name>` and switch to the printed worktree.

## Verify, accept, merge (v0.3.1)

Always run `<main>/.agent-gates/agent-gates`; a copy in an author worktree is not trusted.

After installation, run the installed CLI from any directory:

```bash
/path/to/repo/.agent-gates/agent-gates verify agent/codex --as claude
/path/to/repo/.agent-gates/agent-gates accept <verification-id>
/path/to/repo/.agent-gates/agent-gates merge <acceptance-id>
/path/to/repo/.agent-gates/agent-gates status agent/codex
```

Verify tests a detached worktree of the **merge result**, with the current main
and branch as parents. It also tests main as baseline; `--no-baseline` explicitly
records a skipped baseline. Failed tests still produce a REJECT receipt.
Each test run has its own process group and a `TEST_TIMEOUT_SECONDS` deadline
(default 1800 seconds per run, including baseline). Timeout kills that group,
records `exit=124` and `timed_out=true`, and produces REJECT. Background children
remaining in that group are also cleaned up when the test command exits.
Every CLI copy reads policy only from the main checkout, including the test
command; a worktree-local config cannot override it. Accept and merge reject a
receipt with a different command using `TEST_CMD_MISMATCH`.
Verify records `policy_files_changed` and warns for changes under `.agent-gates/`
or to root `GIT_POLICY.md`, `GIT_POLICY.agent-gates.md`, `VERIFIER.md` and
`VERIFIER.agent-gates.md`. Optional `POLICY_PATHS` adds space-separated globs
matched against repository-relative paths (for example `ops/*.sh docs/security.md`).
Project `bin/` and `init.sh` are ordinary user code unless explicitly matched by
`POLICY_PATHS`. With `POLICY_CHANGES=deny` (default), accept refuses them
with `POLICY_CHANGE_REQUIRES_OVERRIDE` unless the Owner explicitly uses
`accept <id> --allow-policy-change`. This boolean is bound into the acceptance
receipt and signature, and merge rechecks it against main's current policy and
the reviewed diff. `POLICY_CHANGES=warn` keeps warning-only behavior.

Verify also records `test_files_changed` for `tests/`, `test_*`, `*_test.*`,
`conftest.py`, `pytest.ini`, `pyproject.toml`, `setup.cfg`, `tox.ini` and `package.json`.
Accept prints `WARNING: branch changes tests: ...`.
Both policy and test paths use `base...head` (merge-base), excluding main-only changes.
`risk` records `LARGE_DIFF` for more than 1000 added/deleted lines in that diff,
and `LOCKFILE` for `*.lock`, `package-lock.json`, `poetry.lock`, `Cargo.lock` or
`go.sum`. Accept displays these labels as `HIGH_RISK` without another denial.
Accept displays the author, verifier, commits, diffstat, test command and both summaries;
type `yes` to accept, or use `--yes` for scripted use. Acceptance expires after
24 hours by default. A new commit on either branch requires fresh verification.

Merge checks the receipts, optional signature, expiry, both reviewed SHAs,
clean main, exact merge tree and prior use. It prepares a no-fast-forward merge,
checks the tree before committing, and records the merge. A hook that changes the committed tree causes the merge to be rolled back
with `MERGE_RESULT_CHANGED`; existing Git hooks are retained. Gate refusals are one
line `DENY <CODE>: <text>` with exit 1; usage/environment errors exit 2; successful
commands exit 0. Main is not changed by a gate refusal.

Receipts are canonical, content-addressed JSON in
`<git-common-dir>/agent-gates/receipts/`, shared by every worktree and not tracked.
The verification's `<id>.log` holds full merged-result test output;
`<id>.baseline.log` holds baseline output. Each output hash is recorded.

Configuration in `.agent-gates/config`:

```bash
TEST_CMD="python3 -m pytest tests -q"
ACCEPT_TTL_HOURS=24
TEST_TIMEOUT_SECONDS=1800
POLICY_CHANGES=deny
POLICY_PATHS=""
OWNER_NAME="owner"
OWNER_SIGNING_KEY=""
```

Empty `OWNER_SIGNING_KEY` means unsigned acceptances; status shows `UNSIGNED`.
For signed acceptances, set the Owner's private key path and track
`.agent-gates/allowed_signers` with a line such as
`owner ssh-ed25519 <public-key>`. Signatures use namespace `agent-gates`.
The signing payload is canonical acceptance JSON with `signature: null` and
without `id`; both are added afterwards. Keep the private key outside agents'
reach. Signing will be mandatory in the separate enforcement mode.

## Options

| Flag | Default |
|---|---|
| `--agents a,b,c` | `codex,claude` |
| `--test-cmd "…"` | fail closed until configured |
| `--from-defaults` | load `~/.agent-gates/defaults` |
| `--protect p1,p2` | none |
| `--require-locks` | off (unlockable paths become advisory) |
| `--owner` / `--git-agent` / `--orchestrator` / `--publisher` | `owner` / first agent / first agent / owner |
| `--wt-root DIR` | `<repo>-wt` |
| `--backup-dir DIR` | `<repo>/backups` |
| `--dry-run` | — |

## Why: the case that produced this kit

One session on a real production repo (multi-agent platform, ~100 tests, 3 agents):

1. **Master was silently broken.** Agent A had committed a gateway and its tests, but 7 files the gateway depended on sat uncommitted in the main folder for weeks. Running the full suite on master: **9 failures, 7 errors.** Nobody noticed, because each agent only ran "its" tests.
2. **A safety rule existed only on paper.** The policy said a certain class of approvals can never trigger an irreversible external action. The code blocked it only when a limit field was `0`; a missing field defaulted to `-1` and the action went through. The author's report said "all checks pass", and it was true for the checks it ran.
3. **15 tests never ran.** The author reported "28 tests OK", the Verifier ran 88 (one import error). After the fix, `unittest` reported 87 OK, but one file was written for pytest: its 15 tests were never collected. With pytest: **102 passed.**
4. **"Protected" folders were protected by a sentence in a prompt.** Now they're `chattr +i`: even root gets `Operation not permitted`.

None of these were caught by the agent that wrote the code. All of them were caught by a second agent following `VERIFIER.md` and refusing to trust the first one's report.

## Guarantees: what is enforced and what is policy

Be precise about this, because the name says "gates".

| | Enforced by the machine | Policy only (agents are told) |
|---|---|---|
| Separate folder + branch per agent | ✅ git | |
| Locked paths | ✅ OS flag, write-tested | if it shows `NOT LOCKED` |
| Verifier ≠ author, accepted exact merge tree, fresh refs, TTL, no receipt replay | ✅ through the gate CLI | direct Git access can bypass the CLI |
| Test deadlines; policy override under deny mode | ✅ through the gate CLI | direct Git or edited CLI can bypass it |
| Concurrent installation and worktree failure cleanup | ✅ cooperating installers use flock | installation commit is retained for recovery |
| Owner authenticity | ✅ SSH signature when enabled | unsigned acceptances; Verifier identity is supplied with `--as` |
| Only Git Agent can move main | | ⚠️ separate OS users/clones are not part of v0.2 |
| No push | | ⚠️ `GIT_POLICY.md` |

Today an agent running as the same OS user as you **can** ignore the policy rows, and can remove a lock flag it is able to set. Worktrees share one `.git`, so any agent that can commit can also move `main`. Real enforcement needs agents in separate clones under separate OS users, with merges allowed only against a signed approval receipt bound to the reviewed commit SHA. That enforcement mode is separate from v0.2; v0.2 supplies the receipts and CLI checks.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the trust boundary and bypasses.

## What this is not

- Not an orchestrator. It doesn't launch agents, manage tmux, or open PRs. Use it alongside SwarmGit, opentree, agent-worktree or plain terminals.
- Not a sandbox. See the table above.

## Development

```bash
bash tests/test_init.sh   # 28 installation/recovery checks
bash tests/test_setup.sh  # 15 scenarios; isolated HOME and global Git config
bash tests/test_gates.sh  # 29 gate checks, including timeouts, policy override and risk
```

## License

MIT. Built and used in production at [Hlinor](https://hlinor.com).

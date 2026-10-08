# hlinor-agent-gates

**Governance for solo developers running several AI coding agents (Claude Code, Codex, Cursor, Gemini, ZCode, Manus…) on one repository.**

Worktree tools give each agent its own folder, but they don't stop an agent from approving its own work, skipping half your tests, or quietly editing files that should never change. This kit adds the missing gates, in about 2 minutes, on top of whatever you already use.

```
Coder ──► Verifier (a different agent) ──► Owner (you) ──► Git Agent merges
  │            re-runs everything              accepts         only after both
  └── works only in its own worktree
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

`init.sh` checks everything before changing anything. It refuses a dirty working tree (worktrees branch from the last commit, so uncommitted work would be invisible to every agent), refuses to install twice, and never overwrites your files: its own helpers live in `.agent-gates/`, and if `GIT_POLICY.md` exists it writes `GIT_POLICY.agent-gates.md` for you to merge.

Then send each agent the message from `AGENT_ONBOARDING.md`. New agent later:

```bash
.agent-gates/add_agent.sh manus
```

## Verify, accept, merge (v0.2)

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
Every CLI copy reads policy only from the main checkout, including the test
command; a worktree-local config cannot override it. Accept and merge reject a
receipt with a different command using `TEST_CMD_MISMATCH`.
Verify records `policy_files_changed` and warns for changes under `.agent-gates/`,
`bin/` or to `init.sh`. Accept repeats this warning; it does not deny the change.
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
| `--test-cmd "…"` | `python3 -m pytest tests -q` |
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
| Verifier ≠ author, accepted exact merge tree, fresh refs, TTL, no receipt replay | ✅ through the v0.2 CLI | direct Git access can bypass the CLI |
| Owner authenticity | ✅ SSH signature when enabled | unsigned acceptances; Verifier identity is supplied with `--as` |
| Only Git Agent can move main | | ⚠️ separate OS users/clones are not part of v0.2 |
| No push | | ⚠️ `GIT_POLICY.md` |

Today an agent running as the same OS user as you **can** ignore the policy rows, and can remove a lock flag it is able to set. Worktrees share one `.git`, so any agent that can commit can also move `main`. Real enforcement needs agents in separate clones under separate OS users, with merges allowed only against a signed approval receipt bound to the reviewed commit SHA. That enforcement mode is separate from v0.2; v0.2 supplies the receipts and CLI checks.

## What this is not

- Not an orchestrator. It doesn't launch agents, manage tmux, or open PRs. Use it alongside SwarmGit, opentree, agent-worktree or plain terminals.
- Not a sandbox. See the table above.

## Development

```bash
bash tests/test_init.sh   # 26 installation checks
bash tests/test_gates.sh  # 11 required gate scenarios + merge-result, signing, baseline, Git version
```

## License

MIT. Built and used in production at [Hlinor](https://hlinor.com).

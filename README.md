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
| 2 | Roles: Coder / Verifier / Owner / Git Agent. Nobody approves their own work | `GIT_POLICY.md` |
| 3 | Verifier checklist: re-run the **full** suite, compare test counts, check baseline, hunt fail-open defaults | `VERIFIER.md` |
| 4 | Paths agents must never touch | **OS** (`chattr +i` on Linux, `chflags uchg` on macOS), write-tested, not a prompt |
| 5 | One test command for everyone | `GIT_POLICY.md` |
| 6 | No push by agents; verified `git bundle` backups | policy + `.agent-gates/backup.sh` |

## Install

```bash
git clone https://github.com/HlinorAI/hlinor-agent-gates
cd hlinor-agent-gates
./init.sh /path/to/your/repo --agents codex,claude,zcode --owner you --dry-run   # preview
./init.sh /path/to/your/repo --agents codex,claude,zcode --owner you \
  --protect /srv/exports/approved,/srv/sent-mail --require-locks
```

Requirements: git ≥ 2.5, bash, python3. Path locks: Linux needs root + `chattr` on a filesystem that supports it (ext4, xfs); macOS uses `chflags uchg`.

Every lock is **write-tested** after it is applied, and the summary says `LOCKED` or `NOT LOCKED (advisory only)` per path. With `--require-locks`, a path that can't be locked aborts the install before anything else is written.

`init.sh` checks everything before changing anything. It refuses a dirty working tree (worktrees branch from the last commit, so uncommitted work would be invisible to every agent), refuses to install twice, and never overwrites your files: its own helpers live in `.agent-gates/`, and if `GIT_POLICY.md` exists it writes `GIT_POLICY.agent-gates.md` for you to merge.

Then send each agent the message from `AGENT_ONBOARDING.md`. New agent later:

```bash
.agent-gates/add_agent.sh manus
```

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
| Verifier ≠ author, Owner accepts, only Git Agent merges | | ⚠️ `GIT_POLICY.md` |
| No push | | ⚠️ `GIT_POLICY.md` |

Today an agent running as the same OS user as you **can** ignore the policy rows, and can remove a lock flag it is able to set. Worktrees share one `.git`, so any agent that can commit can also move `main`. Real enforcement needs agents in separate clones under separate OS users, with merges allowed only against an approval receipt bound to the reviewed commit SHA. That is v0.2.

## What this is not

- Not an orchestrator. It doesn't launch agents, manage tmux, or open PRs. Use it alongside SwarmGit, opentree, agent-worktree or plain terminals.
- Not a sandbox. See the table above.

## Development

```bash
tests/test_init.sh        # 26 checks: dirty tree, dry run, reinstall, no-overwrite, bad input, backups, locks
```

## License

MIT. Built and used in production at [Hlinor](https://hlinor.com).

# Roadmap — hlinor-agent-gates

Built from 5 independent reviews of v0.3.0 (2026-10-08). Every claim was checked against the code;
items marked **(verified)** were reproduced, items marked **(already covered)** were rejected with the reason.

## Positioning

> A verifiable trust layer between a coding agent, an independent verifier agent, the Owner, and Git.
> Not an orchestrator. Works under whatever runs your agents.

4 of 5 reviews: stay a verification backend (pre-merge gate for SwarmGit, agent-worktree, Cursor, plain terminals).
1 of 5 proposed a TUI / IDE front end. Deferred until enforcement and GitHub integration exist.

## Honest status today (v0.3.0)

| Guarantee | Status |
|---|---|
| Merge-result testing, baseline, fail-closed TEST_CMD, stale-ref DENY, replay DENY | machine-enforced |
| Verifier ≠ author | **self-declared** (`--as`), not proven |
| Owner acceptance | unsigned by default |
| Agents cannot touch main / policy / gate code | **policy only** — same OS user |

Everything below exists to move rows 2–4 into the first row.

---

## v0.3.1 — Hardening (≈1 day)

| # | Item | Reviews | Note |
|---|---|---|---|
| 1 | `TEST_TIMEOUT_SECONDS` (default 1800); kill process group; record timeout in receipt | 1/5 | **(verified)** `subprocess.run` has no timeout — a hanging test hangs verify forever |
| 2 | Warn + list on changes to test files (`tests/`, `conftest.py`, runner config) | 1/5 | **(verified)** a branch can add `conftest.py` that makes everything pass |
| 3 | Policy change mode `POLICY_CHANGES=deny\|warn`; deny requires `accept --allow-policy-change` | 4/5 | today: warning only |
| 4 | HIGH_RISK flag: diff size, lockfile changes | 1/5 | cheap signal for the Owner |
| 5 | Install lock + roll back created worktrees on failure | 2/5 | **(verified)** no rollback after the install commit |
| 6 | Debt from v0.3.0 review: `base...head`, `setup-global` without `--root` warning, `actions/checkout@v5` | — | |
| 7 | Docs: 5-minute quickstart, `THREAT_MODEL.md` (cite HarnessSecurity-Bench, arXiv:2610.07639: auto-approve raised attack success 29.2% → 95.6%), "Supported: Linux, macOS. Not supported: Windows" | 4/5 | |

## v0.4 — Enforced local mode (≈1 week)

Why identity and enforcement ship together: per-agent signing keys are meaningless while all agents run as the same
OS user — any agent can read any other agent's key. Identity becomes real only with separate users.

| # | Item | Reviews |
|---|---|---|
| 1 | One OS user per agent (`agent-codex`, `agent-claude`, …); each works in its own clone, not a shared `.git` | 5/5 |
| 2 | Gate CLI, policy and receipts owned by the Owner/root, read-only for agents | 4/5 |
| 3 | Gatekeeper bare repo: `pre-receive` accepts `main` only with a valid signed acceptance bound to both SHAs | 3/5 |
| 4 | Per-agent SSH keys; verification receipt signed by the verifier; verifier key ≠ author key | 3/5 |
| 5 | Owner signature mandatory in enforced mode; cooperative mode stays opt-in (`--insecure`) | 2/5 |
| 6 | Receipt binds policy hash and test-command hash | 2/5 |
| 7 | `agent-gates doctor` (git, worktrees, users, permissions, keys, stale state) | 2/5 |

**Done when (effect reachability, not command lists):** as an agent OS user, every known path that could move `main` fails —
`git merge`, `git update-ref`, `git push` to the gatekeeper, editing `.git/refs` / `packed-refs`, `git worktree` tricks,
replacing the gate CLI or policy, removing hooks. One test per path; the effect (main unchanged) is asserted, not the error text.
Rationale: HarnessSecurity-Bench (arXiv:2610.07639) found permitted tools leave alternative paths to forbidden operations.

## v0.5 — GitHub integration (≈1 week)

| # | Item | Reviews |
|---|---|---|
| 1 | GitHub Action: verifies receipts (signatures, SHAs, merge tree, TTL, no reuse) as a required status check | 4/5 |
| 2 | `agent-gates github protect`: branch protection, no direct push to main, required check | 4/5 |
| 3 | Receipts published as PR check summary + artifact (audit trail outside `.git`) | 2/5 |

## v0.6 — Observability and integrations

| # | Item | Reviews |
|---|---|---|
| 1 | `status --all`, history, expiring acceptances | 4/5 |
| 2 | Notifications (Telegram / Slack) on verify done / acceptance expiring | 3/5 |
| 3 | Lifecycle: `list-agents`, `remove-agent`, `cleanup`, `export-audit` | 1/5 |
| 4 | Hash-chained audit log | 1/5 |
| 5 | Drop-in pre-merge hook for orchestrators; MCP server exposing verify/accept | 2/5 |

## Rule for every new gate

New DENY rules ship as `warn` first, then move to `deny` by criteria written down before looking at the results.
A gate that never fires is not proven to work: each gate needs a sabotage test showing it fires.
(Lesson from "Mechanizing the User's Eye", arXiv:2610.05981: 12 enforcing days, zero verdicts, precision undefined.)

## Not now

| Idea | Why not yet |
|---|---|
| TUI / VS Code extension | front end before enforcement = polish on advisory checks (1/5) |
| Web dashboard | nothing remote to show until v0.5 |
| Policy engine, runtime safety for external actions | needs identity + enforcement first |
| Windows path locks | document unsupported; revisit on demand |
| Container sandbox for every agent | v0.4 uses OS users; containers optional later |

## Rejected (already covered)

| Claim | Why |
|---|---|
| Uncommitted changes are a blind spot | uncommitted work never reaches main; missing files fail tests in the clean merge-result worktree |
| Old receipts can be replayed for new code | receipts bind `base_sha`, `head_sha`, `merge_tree`; reuse → `RECEIPT_REUSED`, new code → `BRANCH_MOVED` |
| No merge concurrency control | `verify/accept/merge` serialize on `flock`; strict `MAIN_MOVED` |

## Go-to-market (in parallel)

1. Publish this roadmap + 5–7 labelled issues (now).
2. asciinema demo of the full cycle, including three DENYs.
3. Public reference repo with real receipts.
4. Show HN **after v0.4** — when "gates" means agents technically cannot bypass them.
5. Homebrew tap after v0.5.

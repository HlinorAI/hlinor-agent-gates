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

## Observability and lifecycle (v0.6)

Run the trusted main CLI; enforced forms below take the project name immediately
following the command (for example `status my-project --all`).

```bash
GATE=/path/to/main/.agent-gates/agent-gates
"$GATE" status --all --json
"$GATE" history --since 7d
"$GATE" list-agents
"$GATE" check-merge ACCEPTANCE_ID
"$GATE" audit verify --expect-head PREVIOUSLY_SAVED_HASH
"$GATE" export-audit /outside/receipts/audit.tar.gz
"$GATE" cleanup --dry-run
"$GATE" cleanup
"$GATE" remove-agent codex --yes
```

Read commands do not repair evidence. `check-merge` appends one audit event but
changes no refs or receipts. A broken chain blocks verification, acceptance and
merge. Owner `audit reseal --reason 'reviewed explanation'` preserves the discarded
bytes and invalidates receipts from that tail, including unreadable JSON evidence.
They remain on disk and cannot be accepted or merged. Receipts anchor their own
sequence and predecessor; save the audit head externally to detect truncation of
receipt-less events. Exports snapshot the audit, receipts and logs under the gate
lock and include a SHA256 manifest and chain head.

Removal always refuses dirty worktrees, including with `--yes`. Unmerged commits
are printed and their branches and receipts remain. Enforced root uses
`enforce remove-agent PROJECT NAME --yes`: the user is locked, its home archived,
and group membership and registration removed. A user registered in another
project is refused with `AGENT_IN_USE` to preserve that project's home. Cleanup
removes only registered, unheld test resources; foreign files, locks, worktrees,
install-pending markers and evidence stay. Enforced runner exports are registered
by token under the project's `tmp/`; their actual contents in `/tmp` are removed
by the runner UID, never root.

Configure optional hooks in main's policy (ordinary policy override rules apply):

```bash
NOTIFY_CMD="/path/to/trusted-notifier"
NOTIFY_EVENTS="verify,merge,deny,expiring"
```

The hook reads one JSON audit event plus one-line `text` on stdin. It gets 10
seconds; failures are audited and never reverse the gate result or trigger loops.
`status --all --notify` retries failed expiry notifications and deduplicates
successful ones per acceptance. The Owner can schedule the following command,
for example with cron; use root's crontab for enforced mode:

```cron
*/10 * * * * /opt/agent-gates/bin/agent-gates status my-project --all --notify
```

The kit ships `examples/notify/telegram.sh` and `slack.sh` as optional hooks. In
cooperative mode agents share the caller UID and can read notifier secrets.
Enforced mode runs hooks as `ag-notify`, separate from tests and the gate. Put
credentials in `/etc/agent-gates/notify.env` as quoted `NAME=value` assignments
(root:ag-notify, mode 0640); never store them in the repository. Hooks are trusted
Owner code and deliberately have network access. Upgrade an existing enforced
install using the protected root-owned kit's `enforce upgrade PROJECT`.

For Mac publication, the Owner first creates `export-audit` on the server, copies
that file to the Mac, and passes `--audit-export /local/audit.tar.gz` to
`scripts/publish.sh` or `agent-gates publish attest`. The signed attestation includes
`audit_head` (`seq`, `hash`) and the complete exported audit chain. Action checks
canonical hashes, head and receipt sequence/predecessor bindings and ordering.
A same-checkout attestation may use its local audit automatically. Immutable
v0.5 receipts without audit fields retain their old signature checks.
The export contains audit history and receipt evidence: review it before making
it public in attestation notes. Publication uses an Owner-held key; agents do not
publish or acquire that key.

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
| GitHub attestation and receipt validation | ✅ trusted checker pins settings keys and exact evidence | detection requires the workflow to remain enabled and unchanged |
| Audit integrity | ✅ hash chain, receipt anchors; agents cannot write enforced audit | cooperative tail truncation needs a saved external head |
| Expiry notifications | ✅ successful-hook dedupe; enforced separate notifier UID | hook success does not prove delivery; cooperative secrets are agent-readable |
| Agent removal and cleanup | ✅ dirty-worktree refusal, kept evidence, registered resources and locks | Owner decides what unmerged work to archive |
| GitHub PR receipt gate | | ⚠️ advisory in v0.5; a PR can replace its workflow while preserving the required-check name |

In cooperative mode, an agent running as the same OS user as you **can** ignore the policy rows, and can remove a lock flag it is able to set. Worktrees share one `.git`, so any agent that can commit can also move `main`. Real enforcement needs agents in separate clones under separate OS users, with merges allowed only against a signed approval receipt bound to the reviewed commit SHA. Linux enforced mode below makes separate OS users and signed approvals the only gate path; cooperative mode supplies CLI checks.

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

## Enforced mode (Linux)

| Guarantee | Machine boundary in enforced mode | Owner responsibility |
|---|---|---|
| Main updates | restricted pushes; signed acceptance and atomic bare merge | never run agents as root |
| Gate code, policy, keys and receipts | OS ownership, separate UIDs and narrow sudo rules | verify the root-owned release kit |
| Verifier identity and exact tested tree | sudo identity, archive export and gate signature | review test changes and risks |
| Runner persistence | UID process kill, cron/at deny policy and temporary-file cleanup | keep alternative schedulers disabled; run root doctor |
| External publication and network effects | outside this local boundary | external approvals and network policy |


Run `enforce init` only from a root-owned kit checkout whose files and directories
are not writable by group or others, verified against the release tag, for example:

```bash
/root/agent-gates-kit/bin/agent-gates enforce init /path/to/project --agents codex,claude,zcode
```

Never run it from a project's `.agent-gates/`. `UNTRUSTED_SOURCE` prevents loading
a substituted `enforced.py`; it cannot protect you from a substituted
`agent_gates.py` entry point. The Owner must verify the kit before running it as root.
Initialization imports only the committed `main`, ignoring dirty working-tree files.

The project must have a committed `.agent-gates/config` with its real `TEST_CMD`.
Enforced mode requires Linux, Git >= 2.38, Python 3, sudo/visudo, ssh-keygen,
user/group utilities, pkill and find. Cron/at utilities are used when installed.
The Owner must use separate non-root OS accounts to launch agents.

Setup creates `agent-<name>` clones in `/home/agent-<name>/work/<project>`, the gate
in `/opt/agent-gates`, bare repositories in `/srv/agent-gates`, and private state
in `/var/lib/agent-gates`. Agent clones use the restricted `gate` remote.
For a project named `project`, the review flow is:

```bash
# agent-codex, in its own clone:
git push gate agent/codex
# agent-claude, independently:
sudo -u agent-gates /opt/agent-gates/bin/agent-gates verify project agent/codex
# Owner root, using the printed verification ID:
/opt/agent-gates/bin/agent-gates accept <verification-id>
# Git agent, using the printed acceptance ID:
sudo -u agent-gates /opt/agent-gates/bin/agent-gates merge project <acceptance-id>
# Owner root, checking the complete boundary:
/opt/agent-gates/bin/agent-gates doctor project
```

`--as` is rejected: identity comes from sudo. Gate signatures use namespace
`agent-gates-receipt`; mandatory Owner signatures use `agent-gates`. Setup keeps
the Owner key under `/root/.ssh/agent-gates-owner`. Verification/merge receipts
and logs are private to the gate and Owner; `status <project>` exposes validity
through the CLI. Main policy changes invalidate prior verification.

The protected `info/attributes` file disables export-ignore/export-subst even
when a branch changes `.gitattributes`. Root setup denies cron/at use by
ag-runner and removes its existing jobs. Root doctor also checks that systemd
linger is absent. Unprivileged doctor reports `privileged doctor required` for
these checks. Cleanup runs as ag-runner, never root, and fails closed if temporary
files or live processes remain. No extra sudo rights are granted.

Root or a root-launched agent can bypass the boundary. Network isolation and
the GitHub layer below remain separate from OS enforcement. The Owner must not enable alternative
schedulers or change runner permissions after setup. Use cooperative mode on macOS;
Windows is unsupported. Review [THREAT_MODEL.md](THREAT_MODEL.md) for the remaining
policy assumptions.

Run enforced validation only in a disposable container:

```bash
bash tests/test_enforced.sh
```

This script requires a working Docker or Podman runtime; it provisions only inside
the container, mounts the kit read-only, and removes the container afterward.


## GitHub integration (v0.5)

The GitHub layer checks evidence for Owner/admin pushes and provides **advisory PR
verification**. Detection requires the verification workflow to remain enabled and unchanged. `agent-gates/verify` runs on main pushes and PRs into main.
For PRs, it runs the checker from the trusted base commit and treats the PR tree as
Git data. The trusted checker requires a gate merge on the current PR base and its
receipt note. The workflow file itself comes from the PR merge commit: an author
can replace its steps while keeping the required check name. Required checks by
name therefore do not enforce receipt validation against a hostile PR author.
The Owner must review changes to workflows and checker code. A separately pinned
trusted workflow/ruleset is outside v0.5.

Two public-key variables come from GitHub repository settings, never from a commit:

- `AGENT_GATES_OWNER_KEY`: the Mac-only publish key. Every push attestation binds
  repository, previous/new main SHA and the ordered first-parent commit list.
- `AGENT_GATES_ACCEPT_KEYS`: acceptance public keys, one per line, for server-side
  Owner acceptance signatures. A gate merge without this variable fails. A purely
  Owner-attested range with no gate merges needs no acceptance key.

Keep the Mac private key outside agents' reach. Copy only the server acceptance
**public** key to the Mac; do not copy the Mac private key to the server. An
acceptance signature made on a cooperative/root-accessible server binds receipt
bytes to a known key; the Mac publish signature remains the push trust anchor.

Owner/admin setup on the Mac (after existing CI has run at least once):

```bash
./bin/agent-gates github protect --owner-key /private/path/publish.pub \
  --accept-keys /private/path/acceptance-public-keys.txt
# gh must already be authenticated as repository admin.
```

`github protect` preserves existing required checks, review/restriction settings
and discovers current CI check names from main, then adds `agent-gates/verify` and
forbids force pushes and deletion. `--repository owner/repo` selects another repo.
It prints the resulting protection JSON and is idempotent. A different pinned
publish key yields `DENY OWNER_KEY_CHANGED` before writes.

Rotation requires `--rotate --rotation-signature <file>`. Sign the canonical JSON
below (sorted keys, compact separators, UTF-8, no trailing newline) with the old
private key using `ssh-keygen -Y sign -n agent-gates-publish`:

```json
{"kind":"owner-key-rotation","new_key":"ssh-ed25519 <new-base64>","old_key":"ssh-ed25519 <old-base64>","repo":"HlinorAI/hlinor-agent-gates","schema":1,"signature":null}
```

Pass the new public key through `--owner-key`. The signature authorizes that exact
repository and key pair; an absent or invalid old-key signature refuses rotation.

Publish from the Owner's clean main checkout on the Mac, with an existing origin:

```bash
./scripts/publish.sh --source owner@dev-host:/path/to/server-repository \
  --key /private/path/publish --repository HlinorAI/hlinor-agent-gates \
  --audit-export /private/path/server-audit.tar.gz
```

The script fast-forwards from the explicit server source, fetches receipt notes,
reads GitHub's current main, displays the first-parent commit list and asks `y`.
It calls `agent-gates publish attest <old> <new> --key <path> --audit-export <file>` and atomically pushes
the exact main SHA, `refs/notes/agent-gates` and `refs/notes/agent-gates-publish`.
A lease refuses a concurrent change to the reviewed GitHub base. Signing alone is
local: `publish attest` never pushes or calls GitHub API.

The check validates receipt hashes/IDs, acceptance key and lifetime, independent
verifier, tree and ordered parents, policy and acceptance reuse within the range.
Enforced receipts also require gate signatures: Owner acceptance binds the signed
verification bytes, and its embedded SSHSIG public key must also verify the merge.
Cooperative receipts display `UNSIGNED VERIFICATION`, while acceptance must still
be signed by a configured acceptance key.

The check writes a summary and a receipt artifact retained for 90 days. A separate
trusted notification workflow opens or updates one issue titled
`agent-gates: main is unverified` only after a failed push to `main`. It uses default-
branch code and never executes or downloads PR artifacts. PR failures do not open
this issue. Notifications beyond this issue remain out of scope.

Admin pushes cannot be rejected by content: a red check is detection, requiring
someone to review the failure. Branch protection restricts non-admin direct pushes;
PR results remain advisory even when agent-gates/verify is a required check. Losing the Mac key requires an authorized
rotation; leaking it permits forged publish attestations. The Owner must perform
one scratch-repository end-to-end run before release.

Offline validation (no GitHub calls, only temporary test keys):

```bash
bash tests/test_github.sh
bash tests/test_github_tools.sh       # fake gh and fake publication git in PATH
bash tests/test_github_enforced.sh    # disposable Linux container only
```

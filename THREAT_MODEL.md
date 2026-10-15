# Threat model — v0.7.0

Supported: Linux, macOS. Not supported: Windows.

The Owner controls trusted main, its installed CLI/config and optional signing key.
Agents work in linked worktrees and normally share the same OS user and Git common
directory. Always invoke `<main>/.agent-gates/agent-gates`; an author-worktree copy
is not trusted. Verification executes branch code with the caller's OS permissions.

## Machine checks within the supported workflow

| Resource/action | Check | Boundary |
|---|---|---|
| Worktrees | Git creates separate directories and branches | Shared objects, refs and permissions remain |
| Protected paths | OS immutable flags, confirmed by a write attempt | `NOT LOCKED` is advisory; an actor able to clear flags can bypass protection |
| Verification | Tests exact merge tree and optional main baseline using main's TEST_CMD | Test code is untrusted executable code; test quality is not proven |
| Test lifetime | Per-run deadline, own process group, kill on timeout, exit 124 and REJECT | Descendants that escape the group are outside this mechanism |
| Evidence | Canonical receipt ids, hashes, fresh base/head, merge-tree comparison, TTL and replay checks | Unsigned evidence is not authenticated against an actor who can rewrite it |
| Identity | Verifier name differs from author name | `--as` is supplied identity, not proof of independent execution |
| Acceptance | Optional SSH signature in namespace agent-gates | Key and allowed-signers/main policy must remain trustworthy; unsigned acceptance is not Owner authentication |
| Policy edits | Default deny; explicit recorded override, rechecked by merge | Only `.agent-gates/**`, root `GIT_POLICY.md`, `GIT_POLICY.agent-gates.md`, `VERIFIER.md`, `VERIFIER.agent-gates.md` and optional space-separated `POLICY_PATHS` globs match this classifier; warn mode permits acceptance without override |
| Review signals | Test-file warnings, LARGE_DIFF and LOCKFILE labels | Signals do not prove safety or block these risks by themselves |
| Installation | Common-dir flock between installers; cleanup of installer-created worktrees/branches on failure | Cooperating installers only; install commit remains and may need recovery |

Project `bin/` and `init.sh` contain user code and require no policy override unless
the Owner includes them in `POLICY_PATHS` in main's config. Additional globs extend
the fixed policy paths; they do not replace them. Classification is shared by
verify and the accept/merge gate, which recomputes it from bound refs and current
main config instead of trusting legacy receipt path lists.

## Policy rules

GIT_POLICY.md and instruction blocks tell agents to work in their own directory,
read the policy, avoid pushing and leave merges to the Git Agent after independent
verification and Owner acceptance. These instructions cannot enforce who runs Git.
The CLI checks receipts but does not authenticate a designated Git Agent.

## Outside scope

- A same-user actor can run Git directly, move main, bypass the CLI, edit hooks,
  config or code, alter unsigned receipts, or remove the global template setting.
- In cooperative mode a signature alone does not protect main's CLI. Enforced
  mode supplies separate OS users/clones and protected merge code on Linux.
- Tests have no filesystem/network/secret sandbox. A timeout limits the process
  group, not network access or irreversible side effects that ran before timeout.
- Warnings do not ensure complete test coverage, honest summaries or human review.
- Global installation applies only to configured roots and primary checkouts;
  outside roots, missing/deleted hooks or disabled templates can prevent it.
- An installation commit survives worktree failure by design. Recovery must be
  reviewed; externally moved branches are preserved rather than deleted.

These boundaries match the README Guarantees table; passing tests and receipts
are workflow evidence, not a claim that hostile agents are isolated.

## External evidence

[HarnessSecurity-Bench: Do Security Mechanisms Really Protect Coding Agent Harnesses?](https://arxiv.org/abs/2610.07639)
(arXiv:2610.07639, v1) reports 2,500 trials across six coding-agent harnesses
under a controlled GLM-5.2 baseline. In that benchmark, enabling auto-approve
raised attack success from 29.2% to 95.6%. Case studies also found that allowed
tools and commands could provide alternative routes to operations that the
configured restrictions were intended to prevent.

Implication for agent-gates: same-user mode is advisory; enforcement requires separate OS users (v0.4).

## Audit and notification boundaries (v0.6)

Audit JSONL is hash-chained. Inner corruption is detected; receipt anchors detect
loss of their own event. Truncating receipt-less events requires an external
head/sequence, a previously saved export manifest or signed publish attestation.
A cooperative same-user actor can rewrite the complete chain and unsigned
receipts; without an external anchor this remains advisory. Enforced agents
cannot write the audit, receipts, policy or signing key. Reseal is a visible Owner
operation, retains discarded evidence and invalidates its receipt IDs.

Notifier hooks are trusted Owner code. Cooperative hooks share agent-readable
secrets. Enforced hooks run as a distinct `ag-notify` UID, cannot read gate keys,
receipts, private runner exports or agent homes, and load secrets only from a
root-owned group-readable file. A machine-wide gate-side notifier lock serializes
complete-UID cleanup. Timeout, nonzero exit and missing notifier results produce
`notify_failed`, never change the gate outcome, and never notify recursively.
The hook has network access; this is not a network sandbox or a guarantee of
message delivery. Notification success means the hook exited successfully.

Lifecycle runs under the project gate lock. Dirty worktrees are never removed;
branches and evidence are retained. Enforced removal archives rather than
traversing/deleting agent-controlled homes; root status is run as the agent to
avoid executing local clean filters as root. Shared multi-project users require
Owner resolution before archiving. Cleanup trusts only registered gate resources,
respects resource/machine locks and runs runner-file removal as the runner UID.

Publish attestation defaults to `AUDIT_PUBLISH="head"`: only the signed audit
`seq`/`hash` checkpoint is disclosed, alongside existing receipt notes. The Action
checks receipt bounds, strict ordering within and across bundles, unique receipt
IDs, and nondecreasing head sequence versus the previous signed checkpoint on
main's first-parent history. Prior notes must verify against the current pinned
publish key. After key rotation the Owner re-signs the last checkpoint with the
new key, preserving its contents and head; embedded keys are not trust anchors.

Head mode proves ordering and monotonic growth, not the content of non-receipt
events such as DENY. It cannot detect rewriting hidden events, omission of a tail
that never advanced a published checkpoint, or deletion of all external anchors.
Preserve publish notes and independent exported checkpoints. A same-size head
change is not detected by a sequence-only monotonicity check.

Opt-in `AUDIT_PUBLISH="chain"` retains the full chain, canonical hash and receipt
seq/prev/event/invalidation validation, at the cost of publishing audit events.
Both modes still check receipt IDs, signatures and ref bindings; these checks do
not make cooperative evidence resistant to a same-user attacker. Publish and
acceptance keys remain separate. Pre-audit evidence keeps its legacy checks.
PR checks remain advisory as documented in v0.5.

The stdio MCP server exposes only fixed gate commands and strict arguments; it
adds no Owner acceptance or new OS authority. Cooperative identity is still
self-declared. Output is untrusted data even after sanitizing and truncation;
a client must not follow instructions embedded in agent-authored gate fields.
Closing stdin terminates the server and active child group, without answering
queued requests. Configure client deadlines to allow CLI runner cleanup.

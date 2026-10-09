# Threat model — v0.3.1

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
| Policy edits | Default deny; explicit recorded override, rechecked by merge | Only `.agent-gates/`, `bin/`, `init.sh` match this classifier; warn mode permits acceptance without override |
| Review signals | Test-file warnings, LARGE_DIFF and LOCKFILE labels | Signals do not prove safety or block these risks by themselves |
| Installation | Common-dir flock between installers; cleanup of installer-created worktrees/branches on failure | Cooperating installers only; install commit remains and may need recovery |

## Policy rules

GIT_POLICY.md and instruction blocks tell agents to work in their own directory,
read the policy, avoid pushing and leave merges to the Git Agent after independent
verification and Owner acceptance. These instructions cannot enforce who runs Git.
The CLI checks receipts but does not authenticate a designated Git Agent.

## Outside scope

- A same-user actor can run Git directly, move main, bypass the CLI, edit hooks,
  config or code, alter unsigned receipts, or remove the global template setting.
- Separate OS users/clones, mandatory signed acceptance and a protected merge
  service are outside this release. A signature alone does not protect main's CLI.
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

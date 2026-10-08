# Git Policy — {{PROJECT_NAME}}

Status: ACTIVE. Applies to every agent (human or AI) working in this repository.

## Roles

| Role | Who | Can | Cannot |
|---|---|---|---|
| Orchestrator | {{ORCHESTRATOR}} | split work, write task briefs | approve its own briefs' output |
| Coder | any agent | change code in its own worktree, commit to `agent/<name>` | merge, approve own work |
| Verifier | an agent that did NOT write the change | read diff, run checks, give verdict | edit the change under review |
| Owner | {{OWNER}} | accept or reject after Verifier | — |
| Git Agent | {{GIT_AGENT}} | merge `agent/*` into `{{MAIN_BRANCH}}` after Verifier + Owner | change product logic |

Rule zero: **no agent implements and approves its own work.**

## Worktrees

- Each agent works ONLY in `{{WT_ROOT}}/<name>` on branch `agent/<name>`.
- Before starting a task: `git merge {{MAIN_BRANCH}}` in your worktree.
- Never merge into `{{MAIN_BRANCH}}` yourself. Only the Git Agent merges, and only after Verifier ACCEPT and Owner acceptance.
- `{{MAIN_REPO}}` is not a workspace. No edits there.
- New agent: `{{MAIN_REPO}}/scripts/add_agent.sh <name>`.

## Remote and publishing

- Local commits are allowed. `git push` is FORBIDDEN for agents. Do not add remotes.
- Publishing is done only by: {{PUBLISHER}}.
- Backups: `git bundle create <backups>/<project>-<date>.bundle --all`, verified with `git bundle verify`.

## Immutable paths

Locked at the OS level with `chattr -R +i`:
{{PROTECTED_PATHS}}

- "Operation not permitted" there is intentional. Agents must NOT run `chattr`. Stop and ask the Owner.
- Owner unlock: `chattr -R -i <path>`; re-lock after with `chattr -R +i <path>`.

## Tests

- Test runner: `{{TEST_CMD}}`. Use this exact command, nothing else. Different runners collect different tests, and the wrong one skips tests silently.
- A change is offered for review only when the full suite passes. Report the final summary line (e.g. `N passed`).

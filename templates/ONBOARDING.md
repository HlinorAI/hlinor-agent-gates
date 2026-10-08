# Agent onboarding messages — {{PROJECT_NAME}}

Send one of these as the first message of an agent's session. Replace `<name>`.

## Any Coder agent

```
Your working folder: {{WT_ROOT}}/<name> (branch agent/<name>).
1. cd there, run: git merge {{MAIN_BRANCH}}
2. Read GIT_POLICY.md fully before any change.
3. Tests: only `{{TEST_CMD}}`.
4. Never edit {{MAIN_REPO}}, never merge, never push, never change file flags or permissions.
Confirm with: pwd && git branch --show-current
```

## Verifier

```
You are the Verifier for agent/<author>. You did not write it.
Follow VERIFIER.md step by step. Run {{MAIN_REPO}}/.agent-gates/agent-gates verify agent/<author> --as <your-name>; the author's report is a claim.
No edits. Output the verdict block from VERIFIER.md.
```

## Git Agent

```
Owner accepted <commit>, Verifier: ACCEPT.
1. git -C {{MAIN_REPO}} status --short  → must be empty, otherwise stop and report.
2. {{MAIN_REPO}}/.agent-gates/agent-gates merge <acceptance-id>
3. In {{MAIN_REPO}}: {{TEST_CMD}} → report the summary line.
No push. Report git log --oneline -3.
```

## Expected check

`pwd` → `{{WT_ROOT}}/<name>`, branch → `agent/<name>`.

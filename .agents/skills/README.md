# Curated engineering agent skills — pilot

Upstream: https://github.com/mattpocock/skills (MIT License, copyright 2026 Matt Pocock).

Two reviewed files are available in both Codex (`.agents/skills`) and Claude Code (`.claude/skills`):
- diagnosing-bugs — upstream blob d039541ddd1c46e6ddbd662fe99d49b686fc5e12
- handoff — upstream blob a224edc643a20ddb989f9bca1547440169159810

Copies are pinned; updates are manual and require review. The two skill directories contain the same upstream SKILL.md for each agent.

## Boundaries
- Agent Gates repository rules, explicit Owner instructions, and permission/governance controls supersede these third-party skill guides.
- Skill instructions do not authorize commits to protected branches, release/tag publishing, CI reruns, deployments, secret access, communication sending, or external mutations.
- Do not paste tokens, logs with credentials, private email content or customer data into handoffs.
- Do not treat the skill's task recommendations as automatic approval to act.
- Review and validate agent discovery in a locally checked-out PR branch before merging.
- Skills are agent guidance only; they do not modify the runtime gates or permissions.

## Validation
- GitHub PR contains only skill descriptions and documentation, no executable deployment changes.
- Discovery in active Codex/Claude sessions is not independently verified until checked locally.

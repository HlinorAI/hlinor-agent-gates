#!/usr/bin/env bash
# Add a new agent worktree. Part of hlinor-agent-gates.
set -euo pipefail
repo="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
# shellcheck disable=SC1091
source "$repo/.agent-gates/config"
name="${1:?usage: add_agent.sh <name>}"
[[ "$name" =~ ^[a-z0-9-]+$ ]] || { echo "name: a-z 0-9 - only"; exit 1; }
wt="$WT_ROOT/$name"
[ -e "$wt" ] && { echo "already exists: $wt"; exit 1; }
mkdir -p "$WT_ROOT"
git -C "$repo" worktree add -q "$wt" -b "agent/$name" "$MAIN_BRANCH"
echo "OK: $wt on agent/$name"
echo "Switch to: $wt; follow AGENTS.md and GIT_POLICY.md in that worktree"
echo "Next: send the 'Any Coder agent' message from AGENT_ONBOARDING.md with <name>=$name"

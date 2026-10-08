#!/usr/bin/env bash
# hlinor-agent-gates: set up per-agent worktrees, role gates and OS-level path locks
# in an existing git repository.
#
# usage: ./init.sh <repo> [options]
#   --agents a,b,c        agent names (default: codex,claude)
#   --test-cmd "cmd"      the one test command (default: python3 -m pytest tests -q)
#   --protect p1,p2       absolute paths to lock with chattr +i (default: none)
#   --owner NAME          Owner (default: owner)
#   --git-agent NAME      who merges (default: first agent)
#   --orchestrator NAME   (default: first agent)
#   --publisher NAME      who may publish/push (default: Owner)
#   --wt-root DIR         worktrees root (default: <repo>-wt)
#   --backup-dir DIR      bundle backups (default: <repo>/backups)
#   --dry-run             print what would happen, change nothing
set -euo pipefail

KIT="$(cd "$(dirname "$0")" && pwd)"
die() { echo "ERROR: $*" >&2; exit 1; }
say() { echo "• $*"; }

[ $# -ge 1 ] || { sed -n '2,17p' "$0"; exit 1; }
REPO="$(cd "$1" && pwd)"; shift
AGENTS="codex,claude"; TEST_CMD="python3 -m pytest tests -q"; PROTECT=""
OWNER="owner"; GIT_AGENT=""; ORCH=""; PUBLISHER=""; WT_ROOT=""; BACKUP_DIR=""; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --agents) AGENTS="$2"; shift 2;;
    --test-cmd) TEST_CMD="$2"; shift 2;;
    --protect) PROTECT="$2"; shift 2;;
    --owner) OWNER="$2"; shift 2;;
    --git-agent) GIT_AGENT="$2"; shift 2;;
    --orchestrator) ORCH="$2"; shift 2;;
    --publisher) PUBLISHER="$2"; shift 2;;
    --wt-root) WT_ROOT="$2"; shift 2;;
    --backup-dir) BACKUP_DIR="$2"; shift 2;;
    --dry-run) DRY=1; shift;;
    *) die "unknown option $1";;
  esac
done

FIRST="${AGENTS%%,*}"
GIT_AGENT="${GIT_AGENT:-$FIRST}"; ORCH="${ORCH:-$FIRST}"; PUBLISHER="${PUBLISHER:-$OWNER}"
WT_ROOT="${WT_ROOT:-$REPO-wt}"; BACKUP_DIR="${BACKUP_DIR:-$REPO/backups}"
IFS=',' read -r -a AGENT_LIST <<< "$AGENTS"
for a in "${AGENT_LIST[@]}"; do [[ "$a" =~ ^[a-z0-9-]+$ ]] || die "agent name '$a': a-z 0-9 - only"; done

# --- preflight -------------------------------------------------------------
git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1 || die "$REPO is not a git repository"
MAIN_BRANCH="$(git -C "$REPO" branch --show-current)"
[ -n "$MAIN_BRANCH" ] || die "detached HEAD; check out your main branch first"
git -C "$REPO" rev-parse HEAD >/dev/null 2>&1 || die "no commits yet; make an initial commit first"
if [ -n "$(git -C "$REPO" status --porcelain)" ]; then
  git -C "$REPO" status --short | head -20
  die "working tree is not clean. Commit or 'git stash' first: worktrees branch from the last commit and would not see these changes."
fi
for a in "${AGENT_LIST[@]}"; do
  [ -e "$WT_ROOT/$a" ] && die "$WT_ROOT/$a already exists"
  git -C "$REPO" show-ref --quiet "refs/heads/agent/$a" && die "branch agent/$a already exists"
done

PROTECT_MD="- (none configured)"
if [ -n "$PROTECT" ]; then
  PROTECT_MD=""
  IFS=',' read -r -a PROTECT_LIST <<< "$PROTECT"
  for p in "${PROTECT_LIST[@]}"; do
    [[ "$p" = /* ]] || die "protected path must be absolute: $p"
    [ -e "$p" ] || die "protected path does not exist: $p"
    PROTECT_MD+="- \`$p\`"$'\n'
  done
fi

echo "hlinor-agent-gates → $REPO"
say "main branch: $MAIN_BRANCH   worktrees: $WT_ROOT/{${AGENTS}}"
say "roles: orchestrator=$ORCH git-agent=$GIT_AGENT owner=$OWNER publisher=$PUBLISHER"
say "test command: $TEST_CMD"
say "protected: ${PROTECT:-none}"
[ "$DRY" = 1 ] && { echo "dry run: nothing changed"; exit 0; }

# --- render templates -------------------------------------------------------
render() {
  local src="$1" dst="$2"
  if [ -e "$dst" ]; then
    dst="${dst%.md}.agent-gates.md"
    say "exists, writing $(basename "$dst") instead (merge by hand)"
  fi
  PROJECT_NAME="$(basename "$REPO")" MAIN_BRANCH="$MAIN_BRANCH" MAIN_REPO="$REPO" WT_ROOT="$WT_ROOT" \
  TEST_CMD="$TEST_CMD" OWNER="$OWNER" GIT_AGENT="$GIT_AGENT" ORCHESTRATOR="$ORCH" PUBLISHER="$PUBLISHER" \
  PROTECTED_PATHS="$PROTECT_MD" python3 - "$src" "$dst" <<'PY'
import os, re, sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()
def sub(m):
    key = m.group(1)
    if key not in os.environ: raise SystemExit(f"missing template var {key}")
    return os.environ[key].rstrip("\n")
open(dst, "w", encoding="utf-8").write(re.sub(r"\{\{([A-Z_]+)\}\}", sub, text))
PY
}

render "$KIT/templates/GIT_POLICY.md" "$REPO/GIT_POLICY.md"
render "$KIT/templates/VERIFIER.md"   "$REPO/VERIFIER.md"
render "$KIT/templates/ONBOARDING.md" "$REPO/AGENT_ONBOARDING.md"

mkdir -p "$REPO/scripts"
install -m 755 "$KIT/templates/add_agent.sh" "$REPO/scripts/add_agent.sh"
install -m 755 "$KIT/templates/backup.sh"    "$REPO/scripts/backup.sh"
cat > "$REPO/.agent-gates.conf" <<EOF
# written by hlinor-agent-gates init.sh
MAIN_BRANCH="$MAIN_BRANCH"
WT_ROOT="$WT_ROOT"
BACKUP_DIR="$BACKUP_DIR"
EOF

GI="$REPO/.gitignore"
touch "$GI"
for line in "backups/" "*.orig" "__pycache__/"; do grep -qxF "$line" "$GI" || echo "$line" >> "$GI"; done

git -C "$REPO" add GIT_POLICY*.md VERIFIER*.md AGENT_ONBOARDING*.md scripts/add_agent.sh scripts/backup.sh .agent-gates.conf .gitignore
git -C "$REPO" commit -q -m "Add hlinor-agent-gates: roles, worktrees, verifier checklist"
say "committed $(git -C "$REPO" rev-parse --short HEAD)"

# --- worktrees --------------------------------------------------------------
mkdir -p "$WT_ROOT"
for a in "${AGENT_LIST[@]}"; do
  git -C "$REPO" worktree add -q "$WT_ROOT/$a" -b "agent/$a" "$MAIN_BRANCH"
  say "worktree $WT_ROOT/$a on agent/$a"
done

# --- OS-level locks ---------------------------------------------------------
if [ -n "$PROTECT" ]; then
  if [ "$(id -u)" = 0 ] && command -v chattr >/dev/null; then
    for p in "${PROTECT_LIST[@]}"; do
      if chattr -R +i "$p" 2>/dev/null; then say "locked $p"
      else say "WARN: chattr failed on $p (filesystem may not support it). Run by hand: chattr -R +i $p"; fi
    done
  else
    say "WARN: need root + chattr to lock paths. Run: sudo chattr -R +i ${PROTECT//,/ }"
  fi
fi

echo
echo "Done. Next (2 min): send each agent the 'Any Coder agent' message from $REPO/AGENT_ONBOARDING.md"
echo "Check: git -C $REPO worktree list"

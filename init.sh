#!/usr/bin/env bash
# hlinor-agent-gates: set up per-agent worktrees, role gates and OS-level path locks
# in an existing git repository.
#
# usage: ./init.sh <repo> [options]
#   --agents a,b,c        agent names (default: codex,claude)
#   --test-cmd "cmd"      the one test command (default: fail closed)
#   --from-defaults       read ~/.agent-gates/defaults; explicit flags override
#   --protect p1,p2       absolute paths to lock immutable (default: none)
#   --require-locks       abort (changing nothing) if any path cannot be locked
#   --owner NAME          Owner (default: owner)
#   --git-agent NAME      who merges (default: first agent)
#   --orchestrator NAME   (default: first agent)
#   --publisher NAME      who may publish/push (default: Owner)
#   --wt-root DIR         worktrees root (default: <repo>-wt)
#   --backup-dir DIR      bundle backups (default: <repo>/backups)
#   --dry-run             print what would happen, change nothing
set -euo pipefail

VERSION="0.3.0"
KIT="$(cd "$(dirname "$0")" && pwd)"
die() { echo "ERROR: $*" >&2; exit 1; }
say() { echo "• $*"; }

[ $# -ge 1 ] || { sed -n '2,18p' "$0"; exit 1; }
[ -d "$1" ] || die "no such directory: $1"
REPO="$(cd "$1" && pwd -P)"; shift   # -P: macOS /tmp and /var are symlinks
AGENTS="codex,claude"; TEST_CMD=""; PROTECT=""; REQUIRE_LOCKS=0
OWNER="owner"; GIT_AGENT=""; ORCH=""; PUBLISHER=""; WT_ROOT=""; BACKUP_DIR=""; DRY=0
# Load defaults first so explicit flags override regardless of their position.
for option in "$@"; do
  if [ "$option" = --from-defaults ]; then
    defaults_assignments="$(python3 - "$HOME/.agent-gates/defaults" <<'DEFAULTS'
import pathlib, shlex, sys
path = pathlib.Path(sys.argv[1])
if not path.is_file():
    sys.exit('ERROR: missing defaults: ' + str(path))
values = {}
for line in path.read_text().splitlines():
    if not line.strip() or line.lstrip().startswith('#'):
        continue
    key, separator, value = line.partition('=')
    if not separator or key not in ('AGENTS', 'OWNER_NAME', 'TEST_CMD'):
        sys.exit('ERROR: invalid defaults assignment')
    parts = shlex.split(value, comments=True)
    if len(parts) != 1:
        sys.exit('ERROR: invalid defaults value')
    values[key] = parts[0]
for key, value in values.items():
    print(('OWNER' if key == 'OWNER_NAME' else key) + '=' + shlex.quote(value))
DEFAULTS
)" || exit 1
    eval "$defaults_assignments"
    break
  fi
done
while [ $# -gt 0 ]; do
  case "$1" in
    --from-defaults) shift;;
    --agents) AGENTS="$2"; shift 2;;
    --test-cmd) TEST_CMD="$2"; shift 2;;
    --protect) PROTECT="$2"; shift 2;;
    --require-locks) REQUIRE_LOCKS=1; shift;;
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

if [ -z "$TEST_CMD" ]; then
  TEST_CMD="echo 'agent-gates: TEST_CMD not configured' >&2; exit 1"
fi
FIRST="${AGENTS%%,*}"
GIT_AGENT="${GIT_AGENT:-$FIRST}"; ORCH="${ORCH:-$FIRST}"; PUBLISHER="${PUBLISHER:-$OWNER}"
WT_ROOT="${WT_ROOT:-$REPO-wt}"; BACKUP_DIR="${BACKUP_DIR:-$REPO/backups}"
IFS=',' read -r -a AGENT_LIST <<< "$AGENTS"
for a in "${AGENT_LIST[@]}"; do [[ "$a" =~ ^[a-z0-9-]+$ ]] || die "agent name '$a': a-z 0-9 - only"; done
command -v python3 >/dev/null || die "python3 is required"
python3 - <<'VERSION_CHECK'
import re, subprocess, sys
version = re.search(r"(\d+)\.(\d+)", subprocess.check_output(["git", "--version"], text=True))
if not version or tuple(map(int, version.groups())) < (2, 38):
    print("DENY GIT_TOO_OLD: Git 2.38 or later is required")
    sys.exit(1)
VERSION_CHECK


# --- lock backend -------------------------------------------------------------
# Linux: chattr +i (root). macOS: chflags uchg (file owner or root).
OS="$(uname -s)"
LOCK_BACKEND="none"
if [ "$OS" = "Linux" ] && command -v chattr >/dev/null && [ "$(id -u)" = 0 ]; then
  LOCK_BACKEND="chattr"; LOCK_CMD="chattr -R +i"; UNLOCK_CMD="chattr -R -i"
elif [ "$OS" = "Darwin" ] && command -v chflags >/dev/null; then
  LOCK_BACKEND="chflags"; LOCK_CMD="chflags -R uchg"; UNLOCK_CMD="chflags -R nouchg"
else
  LOCK_CMD="(unsupported here)"; UNLOCK_CMD="(unsupported here)"
fi

lock_path()   { $LOCK_CMD "$1" 2>/dev/null; }
unlock_path() { $UNLOCK_CMD "$1" 2>/dev/null || true; }
# A lock counts only if a write attempt actually fails.
lock_holds() {
  local p="$1"
  if [ -d "$p" ]; then
    if ( : > "$p/.agent-gates-locktest" ) 2>/dev/null; then rm -f "$p/.agent-gates-locktest"; return 1; fi
  else
    if ( : >> "$p" ) 2>/dev/null; then return 1; fi
  fi
  return 0
}

# --- preflight (nothing is changed before this section passes) -----------------
git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1 || die "$REPO is not a git repository"
[ "$(git -C "$REPO" rev-parse --show-toplevel)" = "$REPO" ] || die "$REPO is not the repository root"
MAIN_BRANCH="$(git -C "$REPO" branch --show-current)"
[ -n "$MAIN_BRANCH" ] || die "detached HEAD; check out your main branch first"
git -C "$REPO" rev-parse HEAD >/dev/null 2>&1 || die "no commits yet; make an initial commit first"
if [ -n "$(git -C "$REPO" status --porcelain)" ]; then
  git -C "$REPO" status --short | head -20
  die "working tree is not clean. Commit or 'git stash' first: worktrees branch from the last commit and would not see these changes."
fi
[ -e "$REPO/.agent-gates" ] && die "already installed: $REPO/.agent-gates exists (remove it to reinstall)"

# Docs: write NAME.md, or NAME.agent-gates.md if NAME.md exists. Refuse if both exist.
DOC_SRC=(); DOC_DST=()
plan_doc() {
  local src="$1" dst="$2"
  if [ -e "$dst" ]; then
    dst="${dst%.md}.agent-gates.md"
    [ -e "$dst" ] && die "both $(basename "$2") and $(basename "$dst") exist; nothing changed"
  fi
  DOC_SRC+=("$src"); DOC_DST+=("$dst")
}
plan_doc "$KIT/templates/GIT_POLICY.md" "$REPO/GIT_POLICY.md"
plan_doc "$KIT/templates/VERIFIER.md"   "$REPO/VERIFIER.md"
plan_doc "$KIT/templates/ONBOARDING.md" "$REPO/AGENT_ONBOARDING.md"

for a in "${AGENT_LIST[@]}"; do
  [ -e "$WT_ROOT/$a" ] && die "$WT_ROOT/$a already exists"
  git -C "$REPO" show-ref --quiet "refs/heads/agent/$a" && die "branch agent/$a already exists"
done

PROTECT_LIST=()
PROTECT_MD="- (none configured)"
if [ -n "$PROTECT" ]; then
  PROTECT_MD=""
  IFS=',' read -r -a PROTECT_LIST <<< "$PROTECT"
  for p in "${PROTECT_LIST[@]}"; do
    [[ "$p" = /* ]] || die "protected path must be absolute: $p"
    [ -e "$p" ] || die "protected path does not exist: $p"
    PROTECT_MD+="- \`$p\`"$'\n'
  done
  if [ "$LOCK_BACKEND" = "none" ] && [ "$REQUIRE_LOCKS" = 1 ]; then
    die "--require-locks: no lock backend here (Linux needs root + chattr; macOS needs chflags). Nothing changed."
  fi
fi

python3 "$KIT/scripts/instructions.py" --check "$REPO" "$WT_ROOT" "$MAIN_BRANCH"

echo "hlinor-agent-gates $VERSION → $REPO"
say "main branch: $MAIN_BRANCH   worktrees: $WT_ROOT/{${AGENTS}}"
say "roles: orchestrator=$ORCH git-agent=$GIT_AGENT owner=$OWNER publisher=$PUBLISHER"
say "test command: $TEST_CMD"
say "protected: ${PROTECT:-none}   lock backend: $LOCK_BACKEND$([ "$REQUIRE_LOCKS" = 1 ] && echo ' (required)')"
for i in "${!DOC_DST[@]}"; do say "will write ${DOC_DST[$i]#$REPO/}"; done
say "will write .agent-gates/ (config, add_agent.sh, backup.sh)"
[ "$DRY" = 1 ] && { echo "dry run: nothing changed"; exit 0; }

# --- locks first: with --require-locks a failure aborts before anything else ----
LOCK_STATUS=()
if [ ${#PROTECT_LIST[@]} -gt 0 ]; then
  for p in "${PROTECT_LIST[@]}"; do
    if [ "$LOCK_BACKEND" != "none" ] && lock_path "$p" && lock_holds "$p"; then
      LOCK_STATUS+=("LOCKED       $p")
    else
      [ "$LOCK_BACKEND" != "none" ] && unlock_path "$p"
      if [ "$REQUIRE_LOCKS" = 1 ]; then
        for q in "${PROTECT_LIST[@]}"; do [ "$q" = "$p" ] && break; unlock_path "$q"; done
        die "could not lock $p (filesystem may not support it); earlier locks undone, nothing else changed"
      fi
      LOCK_STATUS+=("NOT LOCKED   $p  (advisory only: protected by GIT_POLICY.md text)")
    fi
  done
fi

# --- write files --------------------------------------------------------------
render() {
  PROJECT_NAME="$(basename "$REPO")" MAIN_BRANCH="$MAIN_BRANCH" MAIN_REPO="$REPO" WT_ROOT="$WT_ROOT" \
  TEST_CMD="$TEST_CMD" OWNER="$OWNER" GIT_AGENT="$GIT_AGENT" ORCHESTRATOR="$ORCH" PUBLISHER="$PUBLISHER" \
  PROTECTED_PATHS="$PROTECT_MD" LOCK_CMD="$LOCK_CMD" UNLOCK_CMD="$UNLOCK_CMD" \
  python3 - "$1" "$2" <<'PY'
import os, re, sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()
def sub(m):
    key = m.group(1)
    if key not in os.environ: raise SystemExit(f"missing template var {key}")
    return os.environ[key].rstrip("\n")
open(dst, "x", encoding="utf-8").write(re.sub(r"\{\{([A-Z_]+)\}\}", sub, text))
PY
}
for i in "${!DOC_DST[@]}"; do render "${DOC_SRC[$i]}" "${DOC_DST[$i]}"; done

mkdir "$REPO/.agent-gates"
install -m 755 "$KIT/templates/add_agent.sh" "$REPO/.agent-gates/add_agent.sh"
install -m 755 "$KIT/templates/backup.sh"    "$REPO/.agent-gates/backup.sh"
install -m 755 "$KIT/bin/agent-gates" "$REPO/.agent-gates/agent-gates"
install -m 644 "$KIT/bin/agent_gates.py" "$REPO/.agent-gates/agent_gates.py"
MAIN_BRANCH="$MAIN_BRANCH" WT_ROOT="$WT_ROOT" BACKUP_DIR="$BACKUP_DIR" \
TEST_CMD="$TEST_CMD" OWNER_NAME="$OWNER" python3 - "$REPO/.agent-gates/config" <<'CONFIG'
import os, shlex, sys
with open(sys.argv[1], "x") as stream:
    for key in ("MAIN_BRANCH", "WT_ROOT", "BACKUP_DIR", "TEST_CMD", "OWNER_NAME"):
        stream.write(key + "=" + shlex.quote(os.environ[key]) + "\n")
    stream.write('ACCEPT_TTL_HOURS=24\nTEST_TIMEOUT_SECONDS=1800\nOWNER_SIGNING_KEY=""\n')
CONFIG

GI="$REPO/.gitignore"
touch "$GI"
[ -s "$GI" ] && [ "$(tail -c1 "$GI")" != "" ] && echo >> "$GI"
for line in "backups/" "*.orig" "__pycache__/"; do grep -qxF "$line" "$GI" || echo "$line" >> "$GI"; done

python3 "$KIT/scripts/instructions.py" "$REPO" "$WT_ROOT" "$MAIN_BRANCH"
git -C "$REPO" add .gitignore .agent-gates "${DOC_DST[@]}" AGENTS.md CLAUDE.md GEMINI.md
git -C "$REPO" commit -q -m "Add hlinor-agent-gates $VERSION: roles, worktrees, verifier checklist"
say "committed $(git -C "$REPO" rev-parse --short HEAD)"

# --- worktrees ----------------------------------------------------------------
mkdir -p "$WT_ROOT"
for a in "${AGENT_LIST[@]}"; do
  git -C "$REPO" worktree add -q "$WT_ROOT/$a" -b "agent/$a" "$MAIN_BRANCH"
  say "worktree $WT_ROOT/$a on agent/$a"
done

if [ ${#LOCK_STATUS[@]} -gt 0 ]; then
  echo
  echo "Path locks (write-tested):"
  for s in "${LOCK_STATUS[@]}"; do echo "  $s"; done
fi

echo
echo "Done. Next (2 min): send each agent the 'Any Coder agent' message from AGENT_ONBOARDING.md"
echo "Check: git -C $REPO worktree list"

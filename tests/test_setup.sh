#!/usr/bin/env bash
# v0.3 specification scenarios. Never use the operator's HOME or Git config.
set -uo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd -P)"
T="$(mktemp -d)" || exit 2
T="$(cd "$T" && pwd -P)"
trap 'rm -rf "$T"' EXIT
pass=0; fail=0
check() {
  local name="$1" fn="$2"
  # Fresh isolated machine per scenario; changes cannot spill between tests.
  if ( "$fn" ) >"$T/check.log" 2>&1; then
    echo "PASS $name"; pass=$((pass+1))
  else
    echo "FAIL $name"; cat "$T/check.log"; fail=$((fail+1))
  fi
}
machine() {
  export HOME="$T/$1/home" GIT_CONFIG_GLOBAL="$T/$1/global.gitconfig"
  export GIT_CONFIG_NOSYSTEM=1
  export CODEX_HOME="$HOME/.codex" XDG_CONFIG_HOME="$HOME/.config"
  unset TEST_CMD OWNER_NAME AGENT_GATES_INSTALLING
  mkdir -p "$HOME/.claude" "$HOME/.codex" "$HOME/.gemini" "$T/$1/projects" || return 1
  root="$T/$1/projects"
  git config --global user.name owner && git config --global user.email test@example.com &&
    git config --global init.defaultBranch main || return 1
  for file in "$HOME/.claude/CLAUDE.md" "$HOME/.codex/AGENTS.md" "$HOME/.gemini/GEMINI.md"; do
    printf 'User rules before\n' > "$file"
  done
}
setup() { "$KIT/setup-global.sh" --agents codex,claude,zcode --root "$root" >"$T/setup.log" 2>&1; }
new_repo() {
  r="$1"; mkdir -p "$r" && git -C "$r" init -q -b main || return 1
  printf 'original\n' > "$r/file"
  git -C "$r" add file
}
commit() { git -C "$r" commit -qm "$1" >"$T/commit.log" 2>&1; }
next_commit() {
  printf 'next\n' >> "$r/file"
  git -C "$r" add file && commit next
}
clean() { [ -z "$(git -C "$r" status --porcelain)" ]; }
blocks() {
  local f
  for f in "$@"; do
    [ "$(grep -c '^<!-- agent-gates:begin -->$' "$f")" = 1 ] &&
      [ "$(grep -c '^<!-- agent-gates:end -->$' "$f")" = 1 ] || return 1
  done
}
installed() {
  [ -d "$r/.agent-gates" ] && clean &&
    [ "$(git -C "$r" worktree list --porcelain | grep -c '^worktree ')" = 4 ] &&
    blocks "$r/AGENTS.md" "$r/CLAUDE.md" "$r/GEMINI.md" &&
    [ "$(git -C "$r" log --format=%s | grep -c '^Add hlinor-agent-gates ')" = 1 ]
}
no_install() {
  [ ! -e "$r/.agent-gates" ] && [ ! -e "$r-wt" ] &&
    [ "$(git -C "$r" worktree list --porcelain | grep -c '^worktree ')" = 1 ]
}
global_snapshot() {
  python3 - "$HOME" "$GIT_CONFIG_GLOBAL" <<'PY'
import hashlib,pathlib,sys
home=pathlib.Path(sys.argv[1]); paths=[pathlib.Path(sys.argv[2])]
paths += [home / p for p in ('.agent-gates/defaults','.agent-gates/roots',
                            '.claude/CLAUDE.md','.codex/AGENTS.md','.gemini/GEMINI.md')]
print([(str(p.relative_to(home)) if p.is_relative_to(home) else p.name,
        hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths])
PY
}
t1() {
  machine t1 && setup && new_repo "$root/new" || return 1
  before="$(global_snapshot)"
  commit first && installed && [ "$(global_snapshot)" = "$before" ]
}
t2() {
  machine t2 && setup && new_repo "$T/t2/outside" || return 1
  commit first && no_install && [ ! -s "$T/commit.log" ] && clean &&
    [ ! -e "$r/.git/agent-gates-offered" ] && [ ! -e "$r/.git/agent-gates-pending" ]
}
t3() {
  machine t3 || return 1
  root="$root/root with spaces"; mkdir -p "$root" || return 1
  setup && new_repo "$root/project with spaces" && commit first && installed
}
t4() {
  machine t4 && setup || return 1
  source="$T/t4/source"; mkdir "$source" || return 1
  git -C "$source" init -q -b main --template='' || return 1
  echo source > "$source/file"
  git -C "$source" add file && git -C "$source" commit -qm initial || return 1
  r="$root/clone"
  git clone -q "$source" "$r" || return 1
  next_commit || return 1
  cat "$T/commit.log" > "$T/notices"
  next_commit || return 1
  cat "$T/commit.log" >> "$T/notices"
  no_install && clean && [ -f "$r/.git/agent-gates-offered" ] &&
    [ "$(grep -c '^agent-gates: not installed here.' "$T/notices")" = 1 ]
}
t5() {
  machine t5 || return 1
  r="$root/existing"; mkdir "$r" || return 1
  git -C "$r" init -q -b main --template='' || return 1
  echo old > "$r/file"; git -C "$r" add file
  commit first && next_commit && setup || return 1
  git -C "$r" init -q || return 1
  next_commit || return 1
  cat "$T/commit.log" > "$T/notices"
  next_commit || return 1
  cat "$T/commit.log" >> "$T/notices"
  no_install && clean && [ -z "$(git -C "$r" remote)" ] &&
    [ "$(grep -c '^agent-gates: not installed here.' "$T/notices")" = 1 ]
}
t6() {
  machine t6 && setup && new_repo "$root/dirty" || return 1
  echo deferred > "$r/dirty"
  commit first && no_install && [ -f "$r/.git/agent-gates-pending" ] &&
    [ ! -e "$r/.git/agent-gates-offered" ] || return 1
  # Retry is permitted even with a parent and a newly configured remote.
  git -C "$r" remote add origin https://example.invalid/repo || return 1
  git -C "$r" add dirty && commit clean && installed &&
    [ ! -e "$r/.git/agent-gates-pending" ] && [ ! -e "$r/.git/agent-gates-offered" ]
}
t7() {
  machine t7 && setup && new_repo "$root/recursion" && commit first || return 1
  installed && [ "$(git -C "$r" rev-list --count HEAD)" = 2 ] &&
    [ ! -e "$r/.git/agent-gates-offered" ] && [ ! -e "$r/.git/agent-gates-pending" ]
}
t8() {
  machine t8 && setup && new_repo "$root/user-rules" || return 1
  printf 'My user rules\n<!-- agent-gates:begin -->\nold kit block\n<!-- agent-gates:end -->\nMy suffix\n' > "$r/AGENTS.md"
  git -C "$r" add AGENTS.md && commit first && installed || return 1
  grep -qx 'My user rules' "$r/AGENTS.md" && grep -qx 'My suffix' "$r/AGENTS.md" &&
    ! grep -q 'old kit block' "$r/AGENTS.md" || return 1
  before="$(git -C "$r" rev-parse HEAD)"
  # Reinstall remains refused by v0.1.1; existing instructions stay untouched.
  if "$HOME/.agent-gates/kit/init.sh" "$r" --from-defaults >/dev/null 2>&1; then return 1; fi
  blocks "$r/AGENTS.md" "$r/CLAUDE.md" "$r/GEMINI.md" && clean &&
    [ "$(git -C "$r" rev-parse HEAD)" = "$before" ]
}
t9() {
  machine t9 && setup && new_repo "$root/unknown" && commit first || return 1
  before="$(git -C "$r" rev-parse HEAD)"
  "$r/.agent-gates/add_agent.sh" manus > "$T/add.log" || return 1
  [ "$(git -C "$r-wt/manus" branch --show-current)" = agent/manus ] &&
    grep -q 'Switch to: .*manus; follow AGENTS.md and GIT_POLICY.md' "$T/add.log" &&
    [ "$(git -C "$r" rev-parse HEAD)" = "$before" ] && clean
}
t10() {
  machine t10 && setup || return 1
  before="$(global_snapshot)"
  setup && [ "$(global_snapshot)" = "$before" ] &&
    [ "$(git config --global --get-all init.templateDir | wc -l | tr -d ' ')" = 1 ] &&
    blocks "$HOME/.claude/CLAUDE.md" "$HOME/.codex/AGENTS.md" "$HOME/.gemini/GEMINI.md"
}
t11() {
  machine t11 || return 1
  "$KIT/setup-global.sh" --root "$root" --dry-run >/dev/null || return 1
  [ ! -e "$HOME/.agent-gates" ] || return 1
  git config --global init.templateDir "$T/foreign" || return 1
  before="$(cat "$GIT_CONFIG_GLOBAL")"
  if setup; then return 1; fi
  [ "$(cat "$GIT_CONFIG_GLOBAL")" = "$before" ] && [ ! -e "$HOME/.agent-gates" ] &&
    grep -qx 'User rules before' "$HOME/.claude/CLAUDE.md" &&
    grep -qx 'User rules before' "$HOME/.codex/AGENTS.md" &&
    grep -qx 'User rules before' "$HOME/.gemini/GEMINI.md"
}
t12() {
  machine t12 && setup && new_repo "$root/retained" && commit first || return 1
  before="$(git -C "$r" rev-parse HEAD)"
  "$KIT/setup-global.sh" --uninstall || return 1
  if git config --global --get init.templateDir; then return 1; fi
  for f in "$HOME/.claude/CLAUDE.md" "$HOME/.codex/AGENTS.md" "$HOME/.gemini/GEMINI.md"; do
    grep -qx 'User rules before' "$f" && ! grep -q 'agent-gates:begin' "$f" || return 1
  done
  [ -f "$HOME/.agent-gates/kit/init.sh" ] && installed &&
    [ "$(git -C "$r" rev-parse HEAD)" = "$before" ] &&
    [ "$(git config --global --get user.name)" = owner ]
}
t13() {
  machine t13 && setup && new_repo "$root/unconfigured" && commit first || return 1
  before="$(git -C "$r" rev-parse HEAD)"
  echo feature > "$r-wt/codex/feature"
  git -C "$r-wt/codex" add feature && git -C "$r-wt/codex" commit -qm feature || return 1
  v="$("$r/.agent-gates/agent-gates" verify agent/codex --as claude)" || return 1
  python3 - "$r/.git/agent-gates/receipts/verification-$v.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
assert r['verdict']=='REJECT' and r['result']['exit']==1 and r['baseline']['exit']==1
assert r['test_cmd']=="echo 'agent-gates: TEST_CMD not configured' >&2; exit 1"
PY
  [ "$?" = 0 ] && clean && [ "$(git -C "$r" rev-parse HEAD)" = "$before" ] || return 1
  # Explicit flags win even when --from-defaults is the final option.
  new_repo "$T/t13/overrides" && commit first || return 1
  "$KIT/init.sh" "$r" --agents manus --owner explicit --test-cmd 'echo configured' --from-defaults >/dev/null || return 1
  python3 - "$r/.agent-gates/config" <<'PYCODE'
import shlex,sys
config={}
for line in open(sys.argv[1]):
    key,value=line.strip().split('=',1); config[key]=shlex.split(value)[0]
assert config['OWNER_NAME']=='explicit' and config['TEST_CMD']=='echo configured'
PYCODE
  [ "$?" = 0 ] && clean &&
    [ "$(git -C "$r" worktree list --porcelain | grep -c '^worktree ')" = 2 ] &&
    [ "$(git -C "$r-wt/manus" branch --show-current)" = agent/manus ]
}
t14() {
  machine t14 && setup && new_repo "$root/missing" || return 1
  mv "$HOME/.agent-gates/kit" "$HOME/.agent-gates/kit-hidden" || return 1
  commit first && no_install && clean &&
    [ "$(git -C "$r" rev-list --count HEAD)" = 1 ] &&
    [ "$(wc -l < "$T/commit.log" | tr -d ' ')" = 1 ] &&
    grep -q '^agent-gates: kit missing. Run .*setup-global.sh$' "$T/commit.log"
}
t15() {
  machine t15 || return 1
  "$KIT/setup-global.sh" > "$T/no-roots.log" 2>&1 || return 1
  grep -qx 'WARNING: no roots configured, auto-install disabled' "$T/no-roots.log" &&
    [ ! -s "$HOME/.agent-gates/roots" ] &&
    new_repo "$root/no-roots" && commit first && no_install && [ ! -s "$T/commit.log" ]
}
check '1 new project installs under root' t1
check '2 outside roots is silent' t2
check '3 root and repo paths with spaces' t3
check '4 clone notified once without install' t4
check '5 existing local repo notified once' t5
check '6 dirty first commit retries via pending marker' t6
check '7 recursion guard: one install commit' t7
check '8 user instructions preserved and block unique on re-run' t8
check '9 unknown agent worktree and instructions' t9
check '10 setup is idempotent' t10
check '11 foreign template refused without changes' t11
check '12 uninstall preserves user text, kit and projects' t12
check '13 unconfigured command REJECT, main unchanged' t13
check '14 missing kit notice never fails commit' t14
check '15 empty roots explicitly warn and disable auto-install' t15
echo; echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

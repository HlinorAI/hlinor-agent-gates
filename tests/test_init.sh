#!/usr/bin/env bash
# Regression tests for init.sh. Run: tests/test_init.sh
set -uo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'chattr -R -i "$T" 2>/dev/null; chflags -R nouchg "$T" 2>/dev/null; rm -rf "$T"' EXIT
pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
mkrepo() {
  rm -rf "$T/$1" "$T/$1-wt"; mkdir -p "$T/$1/tests"
  git -C "$T/$1" init -q -b main
  git -C "$T/$1" config user.email t@t; git -C "$T/$1" config user.name t
  echo 'def test_ok(): assert True' > "$T/$1/tests/test_a.py"
  git -C "$T/$1" add -A; git -C "$T/$1" commit -qm init
}
clean() { [ -z "$(git -C "$1" status --porcelain)" ]; }

# 1. dirty tree refused, nothing written
mkrepo r1; echo x > "$T/r1/dirty"
check "dirty tree refused"        bash -c "! '$KIT/init.sh' '$T/r1'"
check "dirty: no files written"   test ! -e "$T/r1/.agent-gates" -a ! -e "$T/r1/GIT_POLICY.md"

# 2. dry run changes nothing
mkrepo r2
check "dry run exits 0"           "$KIT/init.sh" "$T/r2" --dry-run
check "dry run: tree clean"       clean "$T/r2"
check "dry run: no worktrees"     test ! -e "$T/r2-wt"

# 3. normal install
mkrepo r3
check "install"                   "$KIT/init.sh" "$T/r3" --agents codex,claude --owner me
check "install: tree clean"       clean "$T/r3"
check "install: 2 worktrees"      test "$(git -C "$T/r3" worktree list | wc -l)" -eq 3
check "install: no {{ }} left"    bash -c "! grep -q '{{' '$T/r3'/*.md"
check "add_agent from outside"    bash -c "cd / && '$T/r3/.agent-gates/add_agent.sh' manus"
check "backup from outside repo"  bash -c "cd / && '$T/r3/.agent-gates/backup.sh' | grep -q BUNDLE_OK"
check "after backup: tree clean"  clean "$T/r3"

# 4. reinstall refused
check "reinstall refused"         bash -c "! '$KIT/init.sh' '$T/r3' --agents zcode"

# 5. existing user files are never overwritten
mkrepo r5
echo "MY POLICY" > "$T/r5/GIT_POLICY.md"; mkdir -p "$T/r5/scripts"; echo "MINE" > "$T/r5/scripts/backup.sh"
git -C "$T/r5" add -A; git -C "$T/r5" commit -qm user
check "install over user files"   "$KIT/init.sh" "$T/r5"
check "user GIT_POLICY kept"      grep -qx "MY POLICY" "$T/r5/GIT_POLICY.md"
check "user scripts/ kept"        grep -qx "MINE" "$T/r5/scripts/backup.sh"
check "kit policy written aside"  test -f "$T/r5/GIT_POLICY.agent-gates.md"

# 6. both GIT_POLICY.md and GIT_POLICY.agent-gates.md exist → refuse, nothing written
mkrepo r6
echo a > "$T/r6/GIT_POLICY.md"; echo b > "$T/r6/GIT_POLICY.agent-gates.md"
git -C "$T/r6" add -A; git -C "$T/r6" commit -qm user
check "double conflict refused"   bash -c "! '$KIT/init.sh' '$T/r6'"
check "double conflict: untouched" test ! -e "$T/r6/.agent-gates"

# 7. bad inputs
mkrepo r7
check "relative --protect refused" bash -c "! '$KIT/init.sh' '$T/r7' --protect rel/path"
check "missing --protect refused"  bash -c "! '$KIT/init.sh' '$T/r7' --protect '$T/nope'"
check "bad agent name refused"     bash -c "! '$KIT/init.sh' '$T/r7' --agents 'Bad Name'"
check "bad input: untouched"       test ! -e "$T/r7/.agent-gates"

# 8. locks (only where a backend exists)
can_lock=0
{ [ "$(uname -s)" = Linux ] && [ "$(id -u)" = 0 ] && command -v chattr >/dev/null; } && can_lock=1
[ "$(uname -s)" = Darwin ] && can_lock=1
if [ "$can_lock" = 1 ]; then
  mkrepo r8; mkdir -p "$T/locked"
  check "install with --require-locks" "$KIT/init.sh" "$T/r8" --protect "$T/locked" --require-locks
  check "locked dir rejects writes"    bash -c "! touch '$T/locked/x'"
else
  mkrepo r8; mkdir -p "$T/locked"
  check "--require-locks refused without backend" bash -c "! '$KIT/init.sh' '$T/r8' --protect '$T/locked' --require-locks"
  check "refused: untouched"                      test ! -e "$T/r8/.agent-gates"
fi

# 9. repo reached through a symlink (macOS /tmp, /var)
mkrepo r9; ln -s "$T/r9" "$T/r9-link"
check "install via symlinked path" "$KIT/init.sh" "$T/r9-link"

echo; echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

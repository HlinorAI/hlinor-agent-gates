#!/usr/bin/env bash
# Required v0.2 negative scenarios plus merge-result/baseline/installation checks.
set -uo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd -P)"
T="$(mktemp -d)" || exit 2
trap 'rm -rf "$T"' EXIT
pass=0; fail=0; skipped=0
ok() { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
check() {
  if "$2" >"$T/check.log" 2>&1; then ok "$1"
  else bad "$1"; cat "$T/check.log"; fi
}
skip() { echo "SKIP $1 (ssh-keygen unavailable)"; skipped=$((skipped+1)); }
check_signed() {
  if command -v ssh-keygen >/dev/null 2>&1; then check "$@"
  else skip "$1"; fi
}
setup() {
  r="$T/$1"; mkdir -p "$r"
  git -C "$r" init -q -b main || return 1
  git -C "$r" config user.name test; git -C "$r" config user.email test@example.com
  echo '#!/bin/bash' > "$r/check.sh"
  echo 'echo "1 passed"; exit 0' >> "$r/check.sh"
  echo original > "$r/shared"
  git -C "$r" add -A; git -C "$r" commit -qm initial || return 1
  "$KIT/init.sh" "$r" --test-cmd 'bash check.sh' --owner owner >/dev/null || return 1
  cli="$r/.agent-gates/agent-gates"
  receipts="$r/.git/agent-gates/receipts"
  wt="$r-wt/codex"
  echo change > "$wt/feature"
  git -C "$wt" add feature; git -C "$wt" commit -qm feature || return 1
}
verify() { v="$("$cli" verify agent/codex --as claude)" || return 1; }
accept() { a="$("$cli" accept "$v" --yes | tail -1)"; test -f "$receipts/acceptance-$a.json"; }
deny() {
  local code="$1"; shift
  local before after output rc
  before="$(git -C "$r" rev-parse HEAD)"
  output="$("$@" 2>&1)"; rc=$?
  after="$(git -C "$r" rev-parse HEAD)"
  [ "$rc" = 1 ] && [ "$before" = "$after" ] &&
    [ "$(printf '%s\n' "$output" | wc -l | tr -d ' ')" = 1 ] &&
    [[ "$output" == "DENY $code: "* ]]
}
value() {
  python3 - "$1" "$2" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
for key in sys.argv[2].split('.'): r=r[key]
print(r)
PY
}
branch_commit() {
  echo next >> "$wt/feature"
  git -C "$wt" add feature; git -C "$wt" commit -qm next
}
main_commit() {
  echo next > "$r/main-file"
  git -C "$r" add main-file; git -C "$r" commit -qm main-change
}
signed_setup() {
  setup "$1" || return 1
  ssh-keygen -q -t ed25519 -N '' -f "$T/$1-key" || return 1
  printf 'owner %s\n' "$(cat "$T/$1-key.pub")" > "$r/.agent-gates/allowed_signers"
  printf 'OWNER_SIGNING_KEY="%s"\n' "$T/$1-key" >> "$r/.agent-gates/config"
  git -C "$r" add .agent-gates; git -C "$r" commit -qm signing || return 1
}
t1() { setup r1 && deny SELF_VERIFICATION "$cli" verify agent/codex --as codex; }
t2() {
  setup r2 && verify && accept || return 1
  echo dirty > "$r/dirty"
  deny MAIN_DIRTY "$cli" verify agent/codex --as claude &&
    deny MAIN_DIRTY "$cli" merge "$a"
}
t3() {
  setup r3 || return 1
  echo 'echo "0 passed, 1 failed"; exit 1' > "$wt/check.sh"
  git -C "$wt" add check.sh; git -C "$wt" commit -qm failing || return 1
  verify || return 1
  [ "$(value "$receipts/verification-$v.json" verdict)" = REJECT ] &&
    deny NOT_ACCEPTED_BY_VERIFIER "$cli" accept "$v" --yes
}
t4() {
  setup r4 && verify && accept && branch_commit &&
    deny BRANCH_MOVED "$cli" accept "$v" --yes &&
    deny BRANCH_MOVED "$cli" merge "$a"
}
t5() {
  setup r5 && verify && accept && main_commit &&
    deny MAIN_MOVED "$cli" accept "$v" --yes &&
    deny MAIN_MOVED "$cli" merge "$a"
}
t6() {
  setup r6 && verify && accept || return 1
  # Even a whitespace byte changes evidence; canonical file serialization is checked.
  printf '\n' >> "$receipts/verification-$v.json"
  deny RECEIPT_TAMPERED "$cli" accept "$v" --yes &&
    deny RECEIPT_TAMPERED "$cli" merge "$a"
}
t7() {
  signed_setup r7 && verify && accept || return 1
  python3 - "$receipts/acceptance-$a.json" <<'PY'
import json,sys
p=sys.argv[1]; r=json.load(open(p)); r['expires_at']='2099-01-01T00:00:00Z'
open(p,'w').write(json.dumps(r,sort_keys=True,separators=(',',':')))
PY
  deny BAD_SIGNATURE "$cli" merge "$a"
}
t8() {
  setup r8 && verify && accept || return 1
  a="$(python3 - "$receipts/acceptance-$a.json" <<'PY'
import json,sys,hashlib,pathlib
p=pathlib.Path(sys.argv[1]); r=json.loads(p.read_bytes())
r['expires_at']='2000-01-01T00:00:00Z'; del r['id']
dump=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
r['id']=hashlib.sha256(dump(r)).hexdigest()[:12]
(p.parent/('acceptance-'+r['id']+'.json')).write_bytes(dump(r))
print(r['id'])
PY
)" || return 1
  deny ACCEPTANCE_EXPIRED "$cli" merge "$a"
}
t9() {
  setup r9 && verify && accept && "$cli" merge "$a" &&
    deny RECEIPT_REUSED "$cli" merge "$a"
}
t10() {
  setup r10 || return 1
  echo branch > "$wt/shared"; git -C "$wt" add shared; git -C "$wt" commit -qm branch || return 1
  echo main > "$r/shared"; git -C "$r" add shared; git -C "$r" commit -qm main || return 1
  deny MERGE_CONFLICT "$cli" verify agent/codex --as claude
}
t11() {
  setup r11 || return 1
  # CLI works from outside the repository.
  cd / || return 1
  verify && accept || return 1
  "$cli" status agent/codex | grep -q "acceptance $a VALID UNSIGNED" || return 1
  expected="$(value "$receipts/verification-$v.json" merge_tree)"
  "$cli" merge "$a" || return 1
  [ "$(git -C "$r" rev-parse HEAD^{tree})" = "$expected" ] &&
    [ "$(find "$receipts" -name '*.json' | wc -l | tr -d ' ')" = 3 ] &&
    [ -z "$(git -C "$r" status --porcelain)" ] &&
    python3 - "$receipts/verification-$v.json" "$receipts/$v.log" "$receipts/$v.baseline.log" <<'PY'
import hashlib,json,sys
r=json.load(open(sys.argv[1]))
for key,path in zip(('result','baseline'),sys.argv[2:]):
 assert r[key]['output_sha256']==hashlib.sha256(open(path,'rb').read()).hexdigest()
PY
}
t12() {
  setup r12 || return 1
  # Main passes and branch passes, but their combination must REJECT.
  cat > "$r/check.sh" <<'TEST'
if [ -f main-only ] && [ -f branch-only ]; then echo "combination failed"; exit 1; fi
echo "1 passed"
TEST
  git -C "$r" add check.sh; git -C "$r" commit -qm checker || return 1
  git -C "$wt" merge -q main || return 1
  echo x > "$r/main-only"; git -C "$r" add main-only; git -C "$r" commit -qm main-only || return 1
  echo x > "$wt/branch-only"; git -C "$wt" add branch-only; git -C "$wt" commit -qm branch-only || return 1
  (cd "$wt" && bash check.sh) || return 1
  before="$(git -C "$r" rev-parse HEAD)"
  verify || return 1
  [ "$(value "$receipts/verification-$v.json" verdict)" = REJECT ] &&
    [ "$(value "$receipts/verification-$v.json" baseline.exit)" = 0 ] &&
    [ "$(git -C "$r" rev-parse HEAD)" = "$before" ]
}
t13() {
  setup r13 || return 1
  v="$("$cli" verify agent/codex --as claude --no-baseline)" || return 1
  [ "$(value "$receipts/verification-$v.json" baseline.skipped)" = True ] &&
    [ ! -e "$receipts/$v.baseline.log" ]
}
t14() {
  signed_setup r14 && verify && accept && "$cli" merge "$a"
}
t15() {
  setup r15 || return 1
  mkdir "$T/oldgit"
  cat > "$T/oldgit/git" <<'OLD'
#!/bin/bash
echo 'git version 2.37.0'
OLD
  chmod +x "$T/oldgit/git"
  before="$(git -C "$r" rev-parse HEAD)"
  output="$(PATH="$T/oldgit:$PATH" "$cli" status 2>&1)"; rc=$?
  [ "$rc" = 1 ] && [[ "$output" == "DENY GIT_TOO_OLD: "* ]] &&
    [ "$(git -C "$r" rev-parse HEAD)" = "$before" ]
}
t16() {
  setup r16 && verify && accept || return 1
  cat > "$r/.git/hooks/pre-commit" <<'HOOK'
#!/bin/bash
echo changed-by-hook >> feature
git add feature
HOOK
  chmod +x "$r/.git/hooks/pre-commit"
  deny MERGE_RESULT_CHANGED "$cli" merge "$a" &&
    [ -z "$(git -C "$r" status --porcelain)" ] &&
    [ "$(find "$receipts" -name 'merge-*.json' | wc -l | tr -d ' ')" = 0 ]
}
fake_acceptance() {
  # Unsigned attacker fixture: merge must still check verdict and TEST_CMD.
  a="$(python3 - "$receipts/verification-$v.json" <<'PYCODE'
import hashlib,json,pathlib,sys
path=pathlib.Path(sys.argv[1]); verification=json.loads(path.read_bytes())
record={"kind":"acceptance","schema":1,"verification_id":verification["id"],
        "verification_sha256":hashlib.sha256(path.read_bytes()).hexdigest(),
        "owner":"owner","created_at":"2026-10-08T00:00:00Z",
        "expires_at":"2099-01-01T00:00:00Z","signature":None}
dump=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
record["id"]=hashlib.sha256(dump(record)).hexdigest()[:12]
(path.parent/("acceptance-"+record["id"]+".json")).write_bytes(dump(record))
print(record["id"])
PYCODE
)" || return 1
}
t17() {
  setup r17 || return 1
  echo 'echo "0 passed, 1 failed"; exit 1' > "$wt/check.sh"
  git -C "$wt" add check.sh; git -C "$wt" commit -qm failing || return 1
  # Uncommitted override in the author's config must have no effect.
  printf 'TEST_CMD="true"\n' >> "$wt/.agent-gates/config"
  before="$(git -C "$r" rev-parse HEAD)"
  v="$("$wt/.agent-gates/agent-gates" verify agent/codex --as claude)" || return 1
  [ "$(value "$receipts/verification-$v.json" test_cmd)" = "bash check.sh" ] &&
    [ "$(value "$receipts/verification-$v.json" verdict)" = REJECT ] &&
    [ "$(git -C "$r" rev-parse HEAD)" = "$before" ] || return 1
  deny NOT_ACCEPTED_BY_VERIFIER "$cli" accept "$v" --yes &&
    fake_acceptance &&
    deny NOT_ACCEPTED_BY_VERIFIER "$cli" merge "$a"
}
t18() {
  setup r18 && verify || return 1
  owner_output="$("$cli" accept "$v" --yes)" || return 1
  [[ "$owner_output" == *"test_cmd: bash check.sh; tests: "* ]] || return 1
  # Model an old receipt produced by the previous vulnerable CLI.
  v="$(python3 - "$receipts/verification-$v.json" <<'PYCODE'
import hashlib,json,pathlib,sys
path=pathlib.Path(sys.argv[1]); record=json.loads(path.read_bytes())
record["test_cmd"]="true"; del record["id"]
dump=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
record["id"]=hashlib.sha256(dump(record)).hexdigest()[:12]
(path.parent/("verification-"+record["id"]+".json")).write_bytes(dump(record))
print(record["id"])
PYCODE
)" || return 1
  deny TEST_CMD_MISMATCH "$cli" accept "$v" --yes &&
    fake_acceptance &&
    deny TEST_CMD_MISMATCH "$cli" merge "$a"
}
check "1 self verification" t1
check "2 dirty main" t2
check "3 rejected tests cannot be accepted" t3
check "4 branch moved at accept and merge" t4
check "5 main moved at accept and merge" t5
check "6 verification bytes tampered" t6
check_signed "7 signed acceptance tampered" t7
check "8 acceptance expired" t8
check "9 acceptance reused" t9
check "10 conflicting merge" t10
check "11 happy path, receipts, output hashes, UNSIGNED" t11
check "merge result tested, baseline recorded" t12
check "baseline can be explicitly skipped" t13
check_signed "signed happy path" t14
check "old Git refused before effects" t15
check "hook changed tree rolls back merge" t16
check "worktree TEST_CMD override cannot approve failing tests" t17
check "old mismatched runner refused at accept and merge" t18
echo; echo "$pass passed, $fail failed, $skipped skipped"
[ "$fail" -eq 0 ]

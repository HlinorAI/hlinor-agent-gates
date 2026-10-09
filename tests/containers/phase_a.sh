#!/usr/bin/env bash
# Phase A smoke validation: this file is intentionally container-only.
set -euo pipefail
[ -f /.dockerenv ] || [ -f /run/.containerenv ] || { echo 'STOP: disposable container required'; exit 2; }
[ "$(id -u)" = 0 ] || exit 2
# Prepare the trusted distribution inside the disposable container only.
cp -R /kit /trusted-kit
chown -R root:root /trusted-kit
chmod -R go-w /trusted-kit
mkdir -p /tmp/project
cd /tmp/project
git init -q -b main
git config user.name test
git config user.email test@example.com
printf 'ready\n' > message.txt
printf 'set -e\ntest "$(cat message.txt)" = ready\necho "1 passed"\n' > check.sh
git add message.txt check.sh
git commit -qm initial
bash /kit/init.sh /tmp/project --agents codex,claude,zcode --test-cmd 'bash check.sh' >/tmp/cooperative-init.log
base="$(git rev-parse HEAD)"
# An old cooperative copy may contain an attacker-controlled enforced module.
printf 'open("/tmp/untrusted-module-ran", "w").write("executed")\n' > .agent-gates/enforced.py
if bash .agent-gates/agent-gates enforce init /tmp/project --agents codex,claude,zcode >/tmp/untrusted-init.log 2>&1; then exit 1; fi
grep -q '^DENY UNTRUSTED_SOURCE:' /tmp/untrusted-init.log
test ! -e /tmp/untrusted-module-ran
test ! -e /opt/agent-gates
test ! -e /srv/agent-gates
test ! -e /var/lib/agent-gates
test ! -e /etc/sudoers.d/agent-gates
test "$(git rev-parse HEAD)" = "$base"
rm .agent-gates/enforced.py
printf 'PASS untrusted cooperative source rejected before execution or installation\n'
# fsmonitor is a command in an untrusted local Git config, not a trusted test.
printf '#!/bin/sh\ntouch /tmp/fsmonitor-ran\n' > /tmp/evil-fsmonitor
chmod +x /tmp/evil-fsmonitor
git config core.fsmonitor /tmp/evil-fsmonitor
printf '#!/bin/sh\ntouch /tmp/clean-filter-ran\ncat\n' > /tmp/evil-clean
chmod +x /tmp/evil-clean
git config filter.x.clean /tmp/evil-clean
# Deliberately uncommitted: init must not inspect or import the working tree.
printf 'message.txt filter=x\n' > .gitattributes
printf 'dirty\n' > message.txt
bash /trusted-kit/bin/agent-gates enforce init /tmp/project --agents codex,claude,zcode > /tmp/enforce-init.log 2>&1 || { cat /tmp/enforce-init.log; exit 1; }
test ! -e /tmp/fsmonitor-ran
test "$(git -c core.fsmonitor=false rev-parse HEAD)" = "$base"
! grep -q 'untrusted-module-ran' /opt/agent-gates/bin/enforced.py
git -c core.fsmonitor=false config --unset core.fsmonitor
printf 'PASS source Git fsmonitor ignored and main unchanged\n'
test ! -e /tmp/clean-filter-ran
test "$(git --git-dir=/srv/agent-gates/project.git show main:message.txt)" = ready
printf 'PASS clean filter not executed and only committed main imported\n'
/opt/agent-gates/bin/agent-gates doctor project > /tmp/doctor.log 2>&1 || { cat /tmp/doctor.log; exit 1; }
test "$(git --git-dir=/srv/agent-gates/project.git rev-parse main)" = "$base"
visudo -c > /tmp/visudo.log
printf 'PASS initialization, bare main, full doctor and sudoers\n'
before="$(sha256sum /etc/sudoers.d/agent-gates /opt/agent-gates/projects/project.json /var/lib/agent-gates/gate_ed25519)"
bash /trusted-kit/bin/agent-gates enforce init /tmp/project --agents codex,claude,zcode > /tmp/enforce-again.log 2>&1
test "$(sha256sum /etc/sudoers.d/agent-gates /opt/agent-gates/projects/project.json /var/lib/agent-gates/gate_ed25519)" = "$before"
printf 'PASS idempotent init\n'
for name in codex claude zcode; do
  account="agent-$name"; clone="/home/$account/work/project"
  test "$(runuser -u "$account" -- git -C "$clone" branch --show-current)" = "agent/$name"
  test "$(runuser -u "$account" -- git -C "$clone" config remote.gate.url)" = /srv/agent-gates/project.git
  test "$(runuser -u "$account" -- git config --global --get safe.directory)" = '/srv/agent-gates/*'
done
printf 'PASS independent clones and safe.directory\n'
runuser -u agent-codex -- bash -c 'cd /home/agent-codex/work/project; echo feature > feature; git add feature; git commit -qm feature; git push gate agent/codex' > /tmp/push-own.log 2>&1 || { cat /tmp/push-own.log; exit 1; }
expected="$(runuser -u agent-codex -- git -C /home/agent-codex/work/project rev-parse HEAD)"
test "$(git --git-dir=/srv/agent-gates/project.git rev-parse agent/codex)" = "$expected"
test "$(git --git-dir=/srv/agent-gates/project.git rev-parse main)" = "$base"
printf 'PASS own-branch push\n'
for ref in main agent/claude refs/tags/forbidden; do
  if runuser -u agent-codex -- git -C /home/agent-codex/work/project push gate "HEAD:$ref" > /tmp/push-deny.log 2>&1; then exit 1; fi
  test "$(git --git-dir=/srv/agent-gates/project.git rev-parse main)" = "$base"
done
! git --git-dir=/srv/agent-gates/project.git show-ref --verify --quiet refs/heads/agent/claude
! git --git-dir=/srv/agent-gates/project.git show-ref --verify --quiet refs/tags/forbidden
printf 'PASS main, other branch and tag pushes preserve protected refs\n'
for path in /var/lib/agent-gates/gate_ed25519 /root/.ssh/agent-gates-owner; do
  if runuser -u agent-codex -- cat "$path" >/dev/null 2>&1; then exit 1; fi
done
if runuser -u agent-codex -- sudo -n -u agent-gates bash -c 'echo bypass' >/dev/null 2>&1; then exit 1; fi
if runuser -u agent-codex -- sudo -n -u agent-gates SUDO_USER=agent-claude /opt/agent-gates/bin/agent-gates verify project agent/zcode >/dev/null 2>&1; then exit 1; fi
printf 'PASS keys unreadable and sudo/env bypass rejected\n'
/opt/agent-gates/bin/agent-gates doctor project > /tmp/doctor-after-push.log 2>&1 || { cat /tmp/doctor-after-push.log; exit 1; }
# Exercise create, fast-forward and deletion only on the caller's branch.
runuser -u agent-codex -- git -C /home/agent-codex/work/project push gate :agent/codex >/tmp/delete.log 2>&1
! git --git-dir=/srv/agent-gates/project.git show-ref --verify --quiet refs/heads/agent/codex
test "$(git --git-dir=/srv/agent-gates/project.git rev-parse main)" = "$base"
printf 'PASS own-branch deletion and post-push doctor\n'
# root CLI detection uses process identity, not flags supplied to doctor.
bash -c 'exec -a codex sleep 30' & impostor=$!
sleep 0.1
if /opt/agent-gates/bin/agent-gates doctor project >/tmp/root-cli-doctor.log 2>&1; then kill "$impostor"; exit 1; fi
kill "$impostor"; wait "$impostor" || true
grep -q 'NOT ENFORCED no agent CLI running as root' /tmp/root-cli-doctor.log
printf 'PASS doctor rejects root agent CLI\n'
printf '11 passed, 0 failed (phase A container smoke)\n'

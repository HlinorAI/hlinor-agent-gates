#!/usr/bin/env bash
set -euo pipefail
[ -f /.dockerenv ] || [ -f /run/.containerenv ] || exit 2
[ "$(id -u)" = 0 ] || exit 2
cp -R /kit /trusted-kit
chown -R root:root /trusted-kit
chmod -R go-w /trusted-kit
mkdir -p /tmp/rhel-project /var/spool/cron/crontabs
cd /tmp/rhel-project
git init -qb main
git config user.name fixture; git config user.email fixture@local
mkdir .agent-gates
printf 'MAIN_BRANCH=main\nTEST_CMD="true"\n' > .agent-gates/config
git add .; git commit -qm initial
for account in ag-runner ag-notify; do
  echo forbidden > "/var/spool/cron/$account"
  echo forbidden > "/var/spool/cron/crontabs/$account"
done
/trusted-kit/bin/agent-gates enforce init /tmp/rhel-project --agents codex,claude >/tmp/rhel-init.log 2>&1 || { cat /tmp/rhel-init.log; exit 1; }
for account in ag-runner ag-notify; do
  test ! -e "/var/spool/cron/$account"
  test ! -e "/var/spool/cron/crontabs/$account"
done
printf 'PASS 15 RHEL init removes both scheduler spool layouts for both users\n'
for account in ag-runner ag-notify; do
  echo forbidden > "/var/spool/cron/$account"
  if /opt/agent-gates/bin/agent-gates doctor rhel-project >/tmp/rhel-doctor.log 2>&1; then exit 1; fi
  grep -q 'NOT ENFORCED runner has no crontab' /tmp/rhel-doctor.log
  /trusted-kit/bin/agent-gates enforce upgrade rhel-project >/tmp/rhel-upgrade.log 2>&1 || { cat /tmp/rhel-upgrade.log; exit 1; }
  test ! -e "/var/spool/cron/$account"
done
/opt/agent-gates/bin/agent-gates doctor rhel-project >/tmp/rhel-doctor.log 2>&1 || { cat /tmp/rhel-doctor.log; exit 1; }
printf 'PASS 15 RHEL doctor reports spool and upgrade removes it\n'
printf '2 passed, 0 failed\n'

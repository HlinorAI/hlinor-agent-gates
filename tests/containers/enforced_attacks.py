#!/usr/bin/env python3
"""Phase B container integration checks; phase C's release attack suite is separate."""
import hashlib
import grp
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import time

CLI = '/opt/agent-gates/bin/agent-gates'
BARE = '/srv/agent-gates/project.git'
CLONE = '/home/agent-codex/work/project'
RECEIPTS = Path('/var/lib/agent-gates/projects/project/receipts')
passed = 0


def run(*args, ok=True, data=None):
    p = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if ok and p.returncode:
        raise AssertionError(' '.join(args) + '\n' + p.stdout + p.stderr)
    return p


def git(*args):
    return run('runuser', '-u', 'agent-gates', '--', 'git', '-c', 'user.name=gate', '-c', 'user.email=gate@local', '--git-dir='+BARE, *args).stdout.strip()


def gate(user, *args, ok=True):
    return run('runuser', '-u', 'agent-'+user, '--', 'sudo', '-n', '-u', 'agent-gates', CLI, *args, ok=ok)


def main():
    return git('rev-parse', 'main')


def deny_call(user, code, *args):
    before = main()
    p = gate(user, *args, ok=False)
    assert p.returncode == 1 and ('DENY '+code+':') in p.stderr + p.stdout, p.stdout+p.stderr
    assert main() == before


def owner(*args, ok=True):
    return run(CLI, *args, ok=ok)


def owner_deny(code, *args):
    before = main()
    p = owner(*args, ok=False)
    assert p.returncode == 1 and ('DENY '+code+':') in p.stderr+p.stdout, p.stdout+p.stderr
    assert main() == before


def mark(text):
    global passed
    passed += 1
    print('PASS '+text, flush=True)


def branch(files):
    run('runuser', '-u', 'agent-codex', '--', 'git', '-C', CLONE, 'fetch', 'gate', 'main')
    run('runuser', '-u', 'agent-codex', '--', 'git', '-C', CLONE, 'reset', '--hard', 'FETCH_HEAD')
    for name, content in files.items():
        run('runuser', '-u', 'agent-codex', '--', '/usr/bin/python3', '-c',
            'from pathlib import Path; import sys; p=Path(sys.argv[1]); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(sys.argv[2])',
            CLONE+'/'+name, content)
    run('runuser', '-u', 'agent-codex', '--', 'git', '-C', CLONE, 'add', '.')
    run('runuser', '-u', 'agent-codex', '--', 'git', '-C', CLONE, 'commit', '-qm', 'integration change')
    run('runuser', '-u', 'agent-codex', '--', 'git', '-C', CLONE, 'push', '--force', 'gate', 'agent/codex')


def verify():
    return gate('claude', 'verify', 'project', 'agent/codex').stdout.strip().splitlines()[-1]


def read(kind, ident):
    return json.loads((RECEIPTS/(kind+'-'+ident+'.json')).read_bytes())


def canon(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()


def check_signature(record, owner_signature=False):
    signature=Path('/tmp/signature'); signature.write_text(record['signature'])
    allowed=Path('/tmp/allowed')
    if owner_signature:
        allowed.write_text(Path('/opt/agent-gates/owner_allowed_signers').read_text())
    else:
        allowed.write_text('agent-gates '+Path('/var/lib/agent-gates/gate_ed25519.pub').read_text())
    payload=canon({**{k:v for k,v in record.items() if k!='id'},'signature':None})
    run('ssh-keygen','-Y','verify','-f',str(allowed),'-I','root' if owner_signature else 'agent-gates',
        '-n','agent-gates' if owner_signature else 'agent-gates-receipt','-s',str(signature),data=payload.decode())
    assert record['id'] == hashlib.sha256(canon({k:v for k,v in record.items() if k!='id'})).hexdigest()[:12]


def fixture(record, signed=False):
    record=dict(record); record.pop('id',None)
    if signed:
        record['signature']=None
        record['signature']=run('ssh-keygen','-Y','sign','-f','/root/.ssh/agent-gates-owner','-n','agent-gates',data=canon(record).decode()).stdout
    record['id']=hashlib.sha256(canon(record)).hexdigest()[:12]
    path=RECEIPTS/(record['kind']+'-'+record['id']+'.json')
    path.write_bytes(canon(record)); path.chmod(0o600)
    uid=pwd.getpwnam('agent-gates'); os.chown(path,uid.pw_uid,uid.pw_gid)
    return record['id']


# The release suite below counts the 14 spec attacks separately from regressions.
failed = 0

def actor(*args, ok=False):
    return run('runuser','-u','agent-codex','--',*args,ok=ok)


def protected():
    import stat
    values = {}
    for root in ('/opt/agent-gates','/srv/agent-gates','/var/lib/agent-gates',
                 '/root/.ssh','/tmp/project/.agent-gates'):
        for path in [Path(root), *Path(root).rglob('*')]:
            st=path.lstat()
            values[str(path)]=(st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode),
                              hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and not path.is_symlink() else '')
    return values


def attempt(label, action):
    global failed
    before=main()
    try:
        action()
        assert main()==before, 'main moved'
        mark(label)
    except Exception as exc:
        failed+=1
        print('FAIL '+label+': '+str(exc),flush=True)


def no_write(command):
    before=protected()
    p=actor('/bin/bash','-c',command)
    assert p.returncode != 0
    assert protected()==before, 'protected files changed'


def rejected_push(ref):
    before=git('show-ref')
    p=actor('git','-C',CLONE,'push','gate','HEAD:'+ref)
    assert p.returncode != 0 and git('show-ref')==before


branch({'release-feature':'feature\n'})
attempt('01 push main',lambda: rejected_push('main'))
attempt('02 push another agent branch',lambda: rejected_push('agent/claude'))


def raw_writes():
    for path in ('refs/heads/main','packed-refs','objects/attack','config','hooks/pre-receive'):
        no_write('printf attack > '+BARE+'/'+path)
attempt('03 direct bare writes',raw_writes)


def code_writes():
    for path in ('/opt/agent-gates/bin/enforced_runtime.py','/opt/agent-gates/owner_allowed_signers',
                 '/tmp/project/.agent-gates/config'):
        no_write('printf attack > '+path)
attempt('04 gate code and main policy writes',code_writes)

v=verify(); vr=read('verification',v)


def receipt_writes():
    path=str(RECEIPTS/('verification-'+v+'.json'))
    for command in ('printf attack > '+path,'rm '+path,'touch '+str(RECEIPTS/'forged.json')):
        no_write(command)
attempt('05 receipt create/edit/delete',receipt_writes)


def keys():
    before=protected()
    for path in ('/var/lib/agent-gates/gate_ed25519','/root/.ssh/agent-gates-owner'):
        result=actor('cat',path)
        assert result.returncode!=0 and result.stdout==''
    assert protected()==before
attempt('06 private key reads',keys)


def sudo_bypass():
    before=protected()
    for args in (('sudo','-n','-u','agent-gates','bash','-c','touch /opt/agent-gates/bypass'),
                 ('sudo','-n','-u','agent-gates','git','--git-dir='+BARE,'update-ref','refs/heads/main',vr['head_sha']),
                 ('sudo','-n','-u','ag-runner','touch','/dev/shm/sudo-bypass'),
                 ('sudo','-n','-u','root','/opt/agent-gates/bin/runner-cleanup')):
        assert actor(*args).returncode!=0
    assert not Path('/dev/shm/sudo-bypass').exists() and protected()==before
attempt('07 arbitrary sudo and root cleanup',sudo_bypass)


def env_bypass():
    before=protected()
    result=actor('sudo','-n','VAR=x','-u','agent-gates',CLI,'verify','project','agent/codex')
    assert result.returncode!=0 and protected()==before
attempt('08 sudo environment injection',env_bypass)


def self_verify():
    before=protected()
    result=gate('codex','verify','project','agent/codex',ok=False)
    assert result.returncode!=0 and protected()==before
attempt('09 self verification has no receipt',self_verify)


def hostile_tests():
    branch({'check.sh':'''set -e
[ "$(id -un)" = ag-runner ]
! touch /var/lib/agent-gates/runner-attack
! touch /home/agent-codex/work/project/runner-attack
setsid sleep 30 &
echo "1 passed"
'''})
    before_main=main(); before_gate=(Path('/var/lib/agent-gates/gate_ed25519').read_bytes())
    value=verify(); assert read('verification',value)['verdict']=='ACCEPT'
    assert main()==before_main and Path('/var/lib/agent-gates/gate_ed25519').read_bytes()==before_gate
    assert not Path('/var/lib/agent-gates/runner-attack').exists()
    assert not Path(CLONE+'/runner-attack').exists()
    for path in Path('/proc').glob('[0-9]*/status'):
        try:
            text=path.read_text()
            assert not ('Uid:\t'+str(pwd.getpwnam('ag-runner').pw_uid)+'\t') in text
        except FileNotFoundError:
            pass
attempt('10 hostile tests and detached process cleanup',hostile_tests)


def unsigned_merge():
    value=verify(); record={'kind':'acceptance','schema':1,'project':'project','verification_id':value,
        'verification_sha256':hashlib.sha256((RECEIPTS/('verification-'+value+'.json')).read_bytes()).hexdigest(),
        'owner':'root','created_at':'2026-10-09T00:00:00Z','expires_at':'2999-01-01T00:00:00Z',
        'signature':None,'allow_policy_change':False}
    value=fixture(record); before=protected()
    assert gate('codex','merge','project',value,ok=False).returncode!=0
    assert protected()==before
attempt('11 unsigned acceptance cannot merge',unsigned_merge)


def alternate_git():
    before=protected()
    assert actor('git','--git-dir='+BARE,'worktree','add','/tmp/codex-bypass','main').returncode!=0
    assert actor('git','--git-dir='+BARE,'update-ref','refs/heads/main',vr['head_sha']).returncode!=0
    assert protected()==before
attempt('12 worktree and explicit git-dir bypass',alternate_git)


def policy_push():
    before_main=git('rev-parse','main:.agent-gates'); hook=Path(BARE+'/hooks/pre-receive').read_bytes()
    branch({'.agent-gates/config':git('show','main:.agent-gates/config')+'\n# attack\n','pre-receive':'attack\n'})
    expected=actor('git','-C',CLONE,'rev-parse','HEAD',ok=True).stdout.strip()
    assert git('rev-parse','agent/codex')==expected
    value=verify(); before=list(RECEIPTS.glob('acceptance-*'))
    assert owner('accept',value,'--yes',ok=False).returncode!=0
    assert list(RECEIPTS.glob('acceptance-*'))==before
    assert git('rev-parse','main:.agent-gates')==before_main and Path(BARE+'/hooks/pre-receive').read_bytes()==hook
attempt('13 policy-changing push lands only on branch',policy_push)


def root_cli():
    # Owner fixture simulates a misconfigured launcher; inspection is by agent-codex.
    before=protected()
    process=subprocess.Popen(['/bin/bash','-c','exec -a codex sleep 30'])
    try:
        time.sleep(0.1)
        result=actor(CLI,'doctor','project')
        assert result.returncode!=0 and 'NOT ENFORCED no agent CLI running as root' in result.stdout, result.stdout+result.stderr
        assert protected()==before
    finally:
        process.terminate(); process.wait()
attempt('14 root agent CLI detected by doctor',root_cli)


def archive_attack():
    # If Git drops tests/, this command silently succeeds: the failing test must be present.
    branch({'.gitattributes':'tests/ export-ignore\ncheck.sh export-subst\n',
            'nested/.gitattributes':'* export-ignore\n',
            'tests/test_failure.sh':'exit 1\n',
            'check.sh':'set -e; for f in tests/*.sh; do [ -f "$f" ] || continue; bash "$f"; done; echo "0 failed"\n'})
    before=main(); value=verify(); record=read('verification',value)
    assert record['verdict']=='REJECT' and main()==before
    assert '.gitattributes' in record['test_files_changed'] and 'nested/.gitattributes' in record['test_files_changed']
    assert Path(BARE+'/info/attributes').read_text()=='* -export-ignore -export-subst\n'
attempt('15 export-ignore regression and attribute warnings',archive_attack)


def scheduler_attack():
    branch({'check.sh':'''set -e
printf '* * * * * /bin/true\\n' | crontab - && exit 1
printf '/bin/true\\n' | at now + 1 minute && exit 1
printf artifact > /dev/shm/runner-leftover
printf artifact > /var/tmp/runner-leftover
printf artifact > /tmp/runner-leftover
echo "1 passed"
'''})
    value=verify(); assert read('verification',value)['verdict']=='ACCEPT'
    assert not Path('/var/spool/cron/crontabs/ag-runner').exists()
    assert run('atq').stdout.strip()==''
    for root in ('/dev/shm','/var/tmp','/tmp'):
        assert not Path(root+'/runner-leftover').exists()
    uid=pwd.getpwnam('ag-runner').pw_uid
    for root in ('/tmp','/var/tmp','/dev/shm'):
        assert not any(path.lstat().st_uid==uid for path in Path(root).rglob('*'))
attempt('16 cron/at denied and cross-root temporary files removed',scheduler_attack)


def attribute_tamper():
    path=Path(BARE+'/info/attributes'); original=path.read_bytes()
    try:
        path.write_text('* export-ignore\n')
        result=owner('doctor','project',ok=False)
        assert result.returncode!=0 and 'NOT ENFORCED archive attributes project' in result.stdout
    finally:
        path.write_bytes(original)
attempt('17 doctor checks archive attribute hash',attribute_tamper)


def linger_check():
    path=Path('/var/lib/systemd/linger/ag-runner'); path.parent.mkdir(parents=True,exist_ok=True)
    try:
        path.touch()
        assert owner('doctor','project',ok=False).returncode!=0
    finally:
        path.unlink()
    result=actor(CLI,'doctor','project')
    assert result.returncode!=0 and 'privileged doctor required' in result.stdout
attempt('18 root-only scheduler and linger diagnostics',linger_check)


def setup_fixture(name):
    repo=Path('/tmp')/name
    (repo/'.agent-gates').mkdir(parents=True)
    (repo/'.agent-gates/config').write_text('MAIN_BRANCH=main\nTEST_CMD="echo 1 passed"\n')
    run('git','-C',str(repo),'init','-q','-b','main')
    run('git','-C',str(repo),'add','.')
    run('git','-C',str(repo),'-c','user.name=test','-c','user.email=test@local','commit','-qm','initial')
    return repo


def existing_schedules():
    for name in ('cron','at'):
        path=Path('/etc/'+name+'.deny')
        path.write_text('\n'.join(line for line in path.read_text().splitlines() if line.strip()!='ag-runner')+'\n')
    run('crontab','-u','ag-runner','-',data='* * * * * /bin/true\n')
    run('crontab','-u','agent-codex','-',data='* * * * * /bin/true\n')
    other=Path('/var/spool/cron/crontabs/agent-codex').read_bytes()
    run('runuser','-u','ag-runner','--','at','now','+','1','day',data='/bin/true\n')
    assert 'ag-runner' in run('atq').stdout
    repo=setup_fixture('scheduler-cleanup')
    run('/trusted-kit/bin/agent-gates','enforce','init',str(repo))
    assert not Path('/var/spool/cron/crontabs/ag-runner').exists()
    assert 'ag-runner' not in run('atq').stdout
    assert Path('/var/spool/cron/crontabs/agent-codex').read_bytes()==other
    Path('/var/spool/cron/crontabs/agent-codex').unlink()
attempt('19 root init removes old runner cron/at jobs and preserves others',existing_schedules)


def allow_denial():
    repo=setup_fixture('allow-denied')
    base=run('git','-C',str(repo),'rev-parse','main').stdout
    for name in ('cron','at'):
        path=Path('/etc/'+name+'.allow'); original=path.read_bytes() if path.exists() else None
        try:
            path.write_text('ag-runner\n'); path.chmod(0o644)
            result=run('/trusted-kit/bin/agent-gates','enforce','init',str(repo),ok=False)
            assert result.returncode!=0 and not Path('/srv/agent-gates/allow-denied.git').exists()
            assert run('git','-C',str(repo),'rev-parse','main').stdout==base
        finally:
            if original is None: path.unlink()
            else: path.write_bytes(original)
attempt('20 cron.allow and at.allow fail closed',allow_denial)

print(str(passed)+' passed, '+str(failed)+' failed (14 spec attacks + 6 regressions)')
sys.exit(1 if failed else 0)

#!/usr/bin/env python3
"""Disposable Linux container only; real UIDs, fake notifier, no network."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import time

assert Path('/.dockerenv').exists() or Path('/run/.containerenv').exists()
assert os.geteuid()==0
CLI='/opt/agent-gates/bin/agent-gates'
BARE='/srv/agent-gates/project.git'
RECEIPTS=Path('/var/lib/agent-gates/projects/project/receipts')
passed=0


def run(*args,code=0):
    p=subprocess.run([str(a) for a in args],capture_output=True,text=True)
    assert p.returncode==code,(args,p.stdout,p.stderr)
    return p.stdout.strip()


def owner(*args,code=0):return run(CLI,*args,code=code)
def git(*args):return run('git','--git-dir='+BARE,*args)
def mark(name):
    global passed
    passed+=1;print('PASS '+name,flush=True)


try:
    runner=pwd.getpwnam('ag-runner');notify=pwd.getpwnam('ag-notify');gate=pwd.getpwnam('agent-gates')
    secret=Path('/etc/agent-gates/notify.env');secret.write_text('TEST_TOKEN=temporary-fixture-secret\n')
    before=secret.read_bytes()
    private=Path('/home/runner-private');private.mkdir(mode=0o700);os.chown(private,runner.pw_uid,runner.pw_gid)
    runnerfile=private/'secret';runnerfile.write_text('runner evidence');os.chown(runnerfile,runner.pw_uid,runner.pw_gid);runnerfile.chmod(0o600)
    hook=Path('/etc/agent-gates/fake.py')
    hook.write_text('''import json,os,subprocess,sys
from pathlib import Path
message=json.load(sys.stdin)
blocked=[]
for path in ['/var/lib/agent-gates/projects/project/receipts/audit.jsonl','/var/lib/agent-gates/gate_ed25519','/home/runner-private/secret','/home/agent-codex/work/project/check.sh']:
    try:Path(path).read_bytes();blocked.append(False)
    except (PermissionError,FileNotFoundError):blocked.append(True)
subprocess.Popen(['/bin/sh','-c','sleep 2; touch /tmp/notifier-survived'],start_new_session=True)
Path('/tmp/notifier-result').write_text(json.dumps(dict(blocked=blocked,token=os.environ.get('TEST_TOKEN'),message=message)))
sys.exit(0 if all(blocked) else 1)
''')
    os.chown(hook,0,notify.pw_gid);hook.chmod(0o640)
    config='\n'.join(line for line in git('show','main:.agent-gates/config').splitlines() if not line.startswith(('NOTIFY_CMD=','NOTIFY_EVENTS=')))+'\nNOTIFY_CMD="/usr/bin/python3 /etc/agent-gates/fake.py"\nNOTIFY_EVENTS=verify\n'
    tree=git('rev-parse','main^{tree}')
    # Owner fixture changes committed bare policy; no host or external mutation.
    run('git','config','--global','--add','safe.directory',BARE)
    temp=Path('/tmp/owner-policy');run('git','clone','-q',BARE,temp)
    run('git','-C',temp,'config','user.name','owner');run('git','-C',temp,'config','user.email','owner@local')
    (temp/'.agent-gates/config').write_text(config);run('git','-C',temp,'add','.');run('git','-C',temp,'commit','-qm','Owner fake notifier')
    git('fetch',str(temp),'main');git('update-ref','refs/heads/main',git('rev-parse','FETCH_HEAD'))
    run('chown','-R','agent-gates:agents',BARE);run('chmod','-R','g+rX',BARE)
    clone='/home/agent-codex/work/project'
    run('runuser','-u','agent-codex','--','bash','-c','cd '+clone+'; git fetch gate main; git reset --hard FETCH_HEAD; printf "test ! -r /etc/agent-gates/notify.env\\necho 1 passed\\n" > check.sh; git add check.sh; git commit -qm secret-test; git push gate agent/codex')
    main=git('rev-parse','main');key=Path('/var/lib/agent-gates/gate_ed25519').read_bytes()
    result=run('runuser','-u','agent-claude','--','sudo','-n','-u','agent-gates',CLI,'verify','project','agent/codex','--no-baseline')
    v=result.splitlines()[-1];record=json.loads((RECEIPTS/('verification-'+v+'.json')).read_bytes())
    assert record['verdict']=='ACCEPT',record
    output=json.loads(Path('/tmp/notifier-result').read_bytes())
    assert all(output['blocked']) and output['token']=='temporary-fixture-secret'
    assert secret.read_bytes()==before and runnerfile.read_text()=='runner evidence' and Path('/var/lib/agent-gates/gate_ed25519').read_bytes()==key and git('rev-parse','main')==main
    time.sleep(2.5);assert not Path('/tmp/notifier-survived').exists()
    rows=[json.loads(line) for line in (RECEIPTS/'audit.jsonl').read_bytes().splitlines()]
    assert [r['event'] for r in rows][-2:]==['verify','notified']
    processes=subprocess.run(['pgrep','-u',str(notify.pw_uid)],capture_output=True,text=True)
    if processes.returncode==0:
        for pid in processes.stdout.split():assert 'State:\tZ' in Path('/proc/'+pid+'/status').read_text()
    mark('8 notifier/test UID isolation, secrets and full notifier UID cleanup')
    owner('audit','project','verify');mark('notification audit chain remains valid')
    # Root removal uses status as the agent; a malicious clean filter never runs as root.
    run('runuser','-u','agent-codex','--','bash','-c','cd '+clone+'; echo dirty > dirty')
    refusal=subprocess.run([CLI,'enforce','remove-agent','project','codex','--yes'],capture_output=True,text=True)
    assert refusal.returncode==1 and 'DENY DIRTY_WORKTREE:' in refusal.stdout+refusal.stderr
    # Enforced DENY is printed to stderr; returncode and consequences are authoritative.
    assert Path(clone+'/dirty').read_text().strip()=='dirty' and git('rev-parse','main')==main
    Path(clone+'/dirty').unlink()
    other=Path('/opt/agent-gates/projects/other.json')
    other.write_text(json.dumps(dict(users=['agent-codex'])))
    refusal=subprocess.run([CLI,'enforce','remove-agent','project','codex','--yes'],capture_output=True,text=True)
    assert refusal.returncode==1 and 'DENY AGENT_IN_USE:' in refusal.stdout+refusal.stderr
    assert Path(clone).exists() and pwd.getpwnam('agent-codex').pw_dir=='/home/agent-codex'
    assert git('rev-parse','main')==main
    other.unlink()
    mark('shared home guard preserves another project registration and home')
    evidence={p.name:p.read_bytes() for p in RECEIPTS.glob('*.json')}
    branch=git('rev-parse','agent/codex')
    removed=owner('enforce','remove-agent','project','codex','--yes')
    assert 'ARCHIVED ' in removed and not Path('/home/agent-codex').exists()
    archive=Path(removed.split('ARCHIVED ',1)[1].splitlines()[0]);assert (archive/'work/project/check.sh').exists()
    account=pwd.getpwnam('agent-codex');assert pwd.getpwnam('agent-codex').pw_dir==str(archive)
    import grp
    assert grp.getgrnam('agents').gr_gid not in os.getgrouplist(account.pw_name,account.pw_gid)
    assert run('passwd','-S','agent-codex').split()[1]=='L'
    assert owner('enforce','remove-agent','project','codex','--yes')=='ALREADY REMOVED'
    assert git('rev-parse','main')==main and git('rev-parse','agent/codex')==branch
    assert evidence=={p.name:p.read_bytes() for p in RECEIPTS.glob('*.json')}
    mark('9/10 root archives unmerged home, locks user, removes registration/group, keeps evidence')
    root=RECEIPTS.parent/'tmp';root.mkdir(exist_ok=True)
    token='d'*32;export=Path('/tmp/agent-gates-run-'+token);export.mkdir();os.chown(export,runner.pw_uid,runner.pw_gid)
    (export/'keep').write_text('temporary');os.chown(export/'keep',runner.pw_uid,runner.pw_gid)
    marker=root/(token+'.json');marker.write_text(json.dumps(dict(kind='runner',token=token)))
    os.chown(marker,gate.pw_uid,gate.pw_gid);marker.chmod(0o600)
    locks={p:p.read_bytes() for p in (RECEIPTS.parent/'locks').iterdir() if p.is_file()}
    owner('cleanup','project','--dry-run');assert export.exists()
    owner('cleanup','project');assert not export.exists() and not marker.exists()
    assert all(p.read_bytes()==data for p,data in locks.items()) and archive.exists()
    mark('12 enforced cleanup runs as runner, preserves locks, archive and receipts')
    run('runuser','-u','agent-zcode','--','/usr/bin/python3','-c',
        "import shutil;from pathlib import Path;Path('/home/agent-zcode/keep').write_text('evidence');shutil.rmtree('/home/agent-zcode/work/project')")
    removed=owner('enforce','remove-agent','project','zcode','--yes')
    zarchive=Path(removed.split('ARCHIVED ',1)[1].splitlines()[0])
    assert (zarchive/'keep').read_text()=='evidence'
    assert 'agent-zcode' not in json.loads(Path('/opt/agent-gates/projects/project.json').read_bytes())['users']
    assert git('rev-parse','main')==main
    mark('missing clone/unpushed branch cannot prevent enforced user revocation and archive')
    dest='/tmp/audit-export.tar.gz';owner('export-audit','project',dest)
    assert Path(dest).is_file();owner('audit','project','verify');mark('13 root exports complete verified snapshot')
except Exception as exc:
    import traceback;traceback.print_exc()
    print('FAIL '+repr(exc),flush=True);print('%s passed, 1 failed'%passed);sys.exit(1)
print('%s passed, 0 failed'%passed)

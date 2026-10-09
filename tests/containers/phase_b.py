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


try:
    before=list(RECEIPTS.glob('verification-*'))
    deny_call('codex','SELF_VERIFICATION','verify','project','agent/codex')
    deny_call('claude','INVALID_IDENTITY','verify','project','agent/codex','--as','zcode')
    assert list(RECEIPTS.glob('verification-*')) == before
    mark('OS identity, self verification and --as denied without receipts')

    branch({'feature':'approved\n','conftest.py':'# changed tests\n'})
    v=verify(); vr=read('verification',v); check_signature(vr)
    assert vr['verdict']=='ACCEPT' and vr['verifier']=='agent-claude' and vr['author']=='codex'
    assert vr['result']['exit']==vr['baseline']['exit']==0
    assert vr['test_files_changed']==['conftest.py']
    assert vr['policy_sha']==git('rev-parse',vr['base_sha']+':.agent-gates')
    assert vr['test_cmd_sha256']==hashlib.sha256(b'bash check.sh').hexdigest()
    assert hashlib.sha256((RECEIPTS/(v+'.log')).read_bytes()).hexdigest()==vr['result']['output_sha256']
    aout=owner('accept',v,'--yes').stdout; assert 'WARNING: branch changes tests: conftest.py' in aout
    a=aout.strip().splitlines()[-1]; ar=read('acceptance',a); check_signature(ar,True)
    assert ar['owner']=='root'
    m=gate('zcode','merge','project',a).stdout.strip(); mr=read('merge',m); check_signature(mr)
    assert mr['merged_by']=='agent-zcode' and main()==mr['merge_commit']
    assert git('rev-parse','main^{tree}')==vr['merge_tree']
    assert git('rev-list','--parents','-n','1','main').split()[1:]==[vr['base_sha'],vr['head_sha']]
    deny_call('zcode','RECEIPT_REUSED','merge','project',a)
    assert 'merge '+m in gate('codex','status','project').stdout
    mark('signed verify, Owner accept, bare merge tree/parents, replay and status')
    published=RECEIPTS/('merge-'+m+'.json'); pending=RECEIPTS/('pending-'+m+'.json')
    published.rename(pending)
    gate('codex','status','project')
    assert published.exists() and not pending.exists() and main()==mr['merge_commit']
    mark('signed journal recovers a committed merge without moving main')

    branch({'check.sh':'echo fail; exit 1\n'})
    vbad=verify(); assert read('verification',vbad)['verdict']=='REJECT'
    owner_deny('NOT_ACCEPTED_BY_VERIFIER','accept',vbad,'--yes')
    mark('failing tests produce signed REJECT and main remains unchanged')

    branch({'safe':'fresh\n'}); v=verify(); a=owner('accept',v,'--yes').stdout.strip().splitlines()[-1]
    ar=read('acceptance',a); unsigned=fixture({**ar,'signature':None})
    deny_call('zcode','BAD_SIGNATURE','merge','project',unsigned)
    expired=fixture({**ar,'expires_at':'2000-01-01T00:00:00Z'},signed=True)
    deny_call('zcode','ACCEPTANCE_EXPIRED','merge','project',expired)
    tampered=fixture({**ar,'expires_at':'2999-01-01T00:00:00Z'})
    deny_call('zcode','BAD_SIGNATURE','merge','project',tampered)
    for value in (unsigned,expired,tampered):
        (RECEIPTS/('acceptance-'+value+'.json')).unlink()
    mark('mandatory Owner signature, tampered acceptance and signed TTL enforced')

    branch({'safe':'moved\n'})
    owner_deny('BRANCH_MOVED','accept',v,'--yes')
    deny_call('zcode','BRANCH_MOVED','merge','project',a)
    mark('branch freshness enforced for accept and merge')
    path=RECEIPTS/('verification-'+v+'.json'); original=path.read_bytes()
    broken=json.loads(original); broken['result']['exit']=99; path.write_bytes(canon(broken))
    owner_deny('BAD_SIGNATURE','accept',v,'--yes')
    deny_call('zcode','BAD_SIGNATURE','merge','project',a)
    path.write_bytes(original)
    mark('gate signature rejects altered verification evidence')

    v=verify(); a=owner('accept',v,'--yes').stdout.strip().splitlines()[-1]; base=main()
    # A trusted-fixture gate mutation models main moving after review.
    tree=git('rev-parse','main^{tree}')
    moved=git('commit-tree',tree,'-p',base,'-m','main moved')
    git('update-ref','refs/heads/main',moved,base)
    owner_deny('MAIN_MOVED','accept',v,'--yes'); deny_call('zcode','MAIN_MOVED','merge','project',a)
    git('update-ref','refs/heads/main',base,moved)
    mark('strict main freshness enforced')

    # Update committed main policy in a trusted fixture; then return to original main.
    config=git('show',base+':.agent-gates/config')+'\n# policy changed\n'
    idx='/tmp/policy-index'; env=os.environ.copy(); env['GIT_INDEX_FILE']=idx
    def indexed(*args,data=None):
        cmd=['runuser','-u','agent-gates','--','git','-c','user.name=gate','-c','user.email=gate@local','--git-dir='+BARE,*args]
        return subprocess.run(cmd,env=env,input=data,text=True,capture_output=True,check=True).stdout.strip()
    indexed('read-tree',base)
    blob=indexed('hash-object','-w','--stdin',data=config)
    indexed('update-index','--cacheinfo','100644,'+blob+',.agent-gates/config')
    tree=indexed('write-tree'); Path(idx).unlink()
    moved=git('commit-tree',tree,'-p',base,'-m','policy moved'); git('update-ref','refs/heads/main',moved,base)
    owner_deny('POLICY_CHANGED_SINCE_VERIFY','accept',v,'--yes')
    deny_call('zcode','POLICY_CHANGED_SINCE_VERIFY','merge','project',a)
    git('update-ref','refs/heads/main',base,moved)
    mark('policy tree binding checked before main freshness')

    branch({'.agent-gates/config':git('show','main:.agent-gates/config')+'\n# branch policy\n'})
    v=verify(); owner_deny('POLICY_CHANGE_REQUIRES_OVERRIDE','accept',v,'--yes')
    a=owner('accept',v,'--yes','--allow-policy-change').stdout.strip().splitlines()[-1]
    assert read('acceptance',a)['allow_policy_change'] is True
    gate('zcode','merge','project',a)
    assert git('show','main:.agent-gates/config').endswith('# branch policy')
    mark('policy denial, signed Owner override and merge recheck')

    # Change timeout in trusted main policy via the same fixture helper.
    base=main(); config=git('show','main:.agent-gates/config').replace('TEST_TIMEOUT_SECONDS=1800','TEST_TIMEOUT_SECONDS=2')
    indexed('read-tree',base); blob=indexed('hash-object','-w','--stdin',data=config)
    indexed('update-index','--cacheinfo','100644,'+blob+',.agent-gates/config'); tree=indexed('write-tree'); Path(idx).unlink()
    moved=git('commit-tree',tree,'-p',base,'-m','timeout policy'); git('update-ref','refs/heads/main',moved,base)
    branch({'check.sh':'sleep 30\n'})
    t=time.monotonic(); v=verify(); elapsed=time.monotonic()-t; r=read('verification',v)
    assert r['verdict']=='REJECT' and r['result']['exit']==124 and r['result']['timed_out'] and elapsed<10
    assert main()==moved
    assert not list(Path('/tmp').glob('agent-gates-run-*'))
    mark('timeout 124, REJECT, runner process cleanup and export removal')

    # A baseline-only timeout is REJECT even when merged tests pass.
    base=main(); indexed('read-tree',base)
    blob=indexed('hash-object','-w','--stdin',data='sleep 30\n')
    indexed('update-index','--cacheinfo','100644,'+blob+',check.sh')
    tree=indexed('write-tree'); Path(idx).unlink()
    baseline_main=git('commit-tree',tree,'-p',base,'-m','baseline timeout')
    git('update-ref','refs/heads/main',baseline_main,base)
    branch({'check.sh':'echo "1 passed"\n'})
    v=verify(); r=read('verification',v)
    assert r['result']['exit']==0 and r['baseline']['exit']==124 and r['baseline']['timed_out']
    assert r['verdict']=='REJECT' and main()==baseline_main
    git('update-ref','refs/heads/main',base,baseline_main)
    mark('baseline-only timeout remains REJECT')

    branch({'check.sh':'''set -e
[ "$(id -un)" = ag-runner ]
[ ! -e .git ]
! touch /var/lib/agent-gates/test-write
! touch /home/agent-codex/work/project/test-write
! cat /root/.ssh/agent-gates-owner
! cat /var/lib/agent-gates/gate_ed25519
setsid sleep 30 &
mkdir -p readonly/inner
echo content > readonly/inner/file
chmod 000 readonly/inner/file
chmod 000 readonly/inner
chmod 000 readonly
echo "1 passed as ag-runner"
'''})
    v=verify(); r=read('verification',v)
    assert r['verdict']=='ACCEPT' and r['result']['summary']=='1 passed as ag-runner', repr(r['result'])+'\n'+(RECEIPTS/(v+'.log')).read_text()
    assert not Path('/var/lib/agent-gates/test-write').exists()
    assert not Path(CLONE+'/test-write').exists()
    assert not list(Path('/tmp').glob('agent-gates-run-*'))
    assert main()==base
    mark('real runner UID, no .git, protected writes/keys denied, detached child killed')

    branch({'large.txt':'x\n'*1001,'Cargo.lock':'locked\n'})
    v=verify(); r=read('verification',v)
    assert r['risk']==['LARGE_DIFF','LOCKFILE']
    assert 'HIGH_RISK: LARGE_DIFF, LOCKFILE' in owner('accept',v,'--yes').stdout
    mark('HIGH_RISK fields and Owner display preserved')

    # Verify distinct projects concurrently: per-project locks cannot satisfy this.
    branch({'check.sh':'sleep 1; echo "1 passed"\n'})
    second=Path('/tmp/second'); (second/'.agent-gates').mkdir(parents=True)
    (second/'check.sh').write_text('sleep 1; echo "1 passed"\n')
    (second/'.agent-gates/config').write_text('MAIN_BRANCH=main\nTEST_CMD="bash check.sh"\nTEST_TIMEOUT_SECONDS=2\n')
    run('git','-C',str(second),'init','-q','-b','main')
    run('git','-C',str(second),'add','.')
    run('git','-C',str(second),'-c','user.name=test','-c','user.email=test@local','commit','-qm','initial')
    run('/trusted-kit/bin/agent-gates','enforce','init',str(second))
    other='/home/agent-codex/work/second'
    run('runuser','-u','agent-codex','--','git','-C',other,'commit','--allow-empty','-qm','change')
    run('runuser','-u','agent-codex','--','git','-C',other,'push','gate','agent/codex')
    t=time.monotonic()
    prefix=['runuser','-u','agent-claude','--','sudo','-n','-u','agent-gates',CLI,'verify']
    p1=subprocess.Popen(prefix+['project','agent/codex','--no-baseline'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    p2=subprocess.Popen(prefix+['second','agent/codex','--no-baseline'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    out1,err1=p1.communicate(); out2,err2=p2.communicate()
    assert p1.returncode==p2.returncode==0, err1+err2
    assert time.monotonic()-t>=2
    assert read('verification',out1.strip())['verdict']=='ACCEPT'
    second_receipt=Path('/var/lib/agent-gates/projects/second/receipts/verification-'+out2.strip()+'.json')
    assert json.loads(second_receipt.read_bytes())['verdict']=='ACCEPT'
    mark('machine-wide runner lock serializes different projects')

    owner('doctor','project')
    mark('post-workflow doctor passes')
    print(str(passed)+' passed, 0 failed (phase B container integration)')
except Exception as exc:
    for path in Path(BARE+'/objects').rglob('*'):
        st=path.stat()
        if st.st_gid != grp.getgrnam("agents").gr_gid or not st.st_mode & 0o040 or (path.is_dir() and not st.st_mode & 0o010):
            print('OBJECT_MODE', oct(st.st_mode), st.st_uid, st.st_gid, str(path), file=sys.stderr)
    print(str(exc),file=sys.stderr)
    print(str(passed)+' passed, 1 failed (phase B container integration)')
    raise

#!/usr/bin/env python3
"""Run only inside disposable root container after phase_a.sh."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

assert Path('/.dockerenv').exists() or Path('/run/.containerenv').exists()
assert os.geteuid()==0
CLI='/opt/agent-gates/bin/agent-gates'
RECEIPTS=Path('/var/lib/agent-gates/projects/project/receipts')
passed=0


def run(args,code=0):
    p=subprocess.run(args,text=True,capture_output=True)
    assert p.returncode==code,(args,p.stdout,p.stderr)
    return p.stdout.strip()


def gate(command,*args,code=0):
    return run(['runuser','-u','agent-codex','--','sudo','-n','-u','agent-gates',CLI,command,'project',*args],code)


def reviewer(*args,code=0):
    return run(['runuser','-u','agent-claude','--','sudo','-n','-u','agent-gates',CLI,*args],code)


def owner(*args,code=0):
    return run([CLI,*args],code)


def snapshot():
    return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in RECEIPTS.iterdir() if p.is_file()}


def mark(text):
    global passed
    passed+=1; print('PASS '+text,flush=True)


try:
    # Prepare an actual agent commit and push only to the disposable local gate.
    clone='/home/agent-codex/work/project'
    run(['runuser','-u','agent-codex','--','bash','-c',
         'cd '+clone+'; echo audit > audit-feature; git add audit-feature; git commit -qm audit; git push gate agent/codex'])
    v=reviewer('verify','project','agent/codex','--no-baseline').splitlines()[-1]
    a=owner('accept',v,'--yes').splitlines()[-1]
    main=run(['git','--git-dir=/srv/agent-gates/project.git','rev-parse','main'])
    before=snapshot()
    assert json.loads(gate('history','--json'))
    assert len(json.loads(gate('list-agents','--json')))==3
    assert json.loads(gate('status','--all','--json'))[0]['verification']=='ACCEPT'
    assert before==snapshot()
    assert gate('check-merge',a)=='OK'
    assert before=={k:v for k,v in snapshot().items() if k!='audit.jsonl'} | {'audit.jsonl':before['audit.jsonl']}
    assert run(['git','--git-dir=/srv/agent-gates/project.git','rev-parse','main'])==main
    mark('14 real agent history/list/status read paths and check-merge preserve receipts and main')
    for args in [('status','project','--all','--notify'),('audit','project','reseal','--reason','attack'),
                 ('export-audit','project','/tmp/stolen.tar.gz'),('cleanup','project')]:
        result=subprocess.run(['runuser','-u','agent-codex','--','sudo','-n','-u','agent-gates',CLI,*args],text=True,capture_output=True)
        assert result.returncode!=0
        if args[0]=='status': assert 'DENY ROOT_REQUIRED:' in result.stderr+result.stdout
    assert run(['git','--git-dir=/srv/agent-gates/project.git','rev-parse','main'])==main
    mark('14 agent cannot notify, reseal, export or cleanup')
    assert owner('audit','project','verify').startswith('OK')
    rows=[json.loads(line) for line in (RECEIPTS/'audit.jsonl').read_text().splitlines()]
    for path in RECEIPTS.glob('*.json'):
        r=json.loads(path.read_bytes()); row=rows[r['audit_seq']-1]
        assert row['receipt']==r['id'] and row['prev']==r['audit_prev'] and r.get('signature')
    result=subprocess.run(['runuser','-u','agent-codex','--','cat',str(RECEIPTS/'audit.jsonl')],capture_output=True)
    assert result.returncode!=0
    mark('signed receipt anchors and audit inaccessible to real agent')
    log=RECEIPTS/'audit.jsonl'
    seq=len(rows)+1
    log.chmod(0o400)
    refused=reviewer('verify','project','agent/codex','--no-baseline',code=1)
    # Enforced refusals are on stderr, so inspect the receipt and audit directly.
    orphan=[json.loads(path.read_bytes()) for path in RECEIPTS.glob('verification-*.json')
            if json.loads(path.read_bytes())['audit_seq']==seq]
    assert len(orphan)==1 and len(log.read_text().splitlines())==seq-1
    log.chmod(0o600)
    reviewer('verify','project','agent/codex','--no-baseline')
    restored=[json.loads(line) for line in log.read_text().splitlines()][seq-1]
    assert restored['event']=='recovered' and restored['receipt']==orphan[0]['id']
    assert restored['seq']==seq and restored['prev']==orphan[0]['audit_prev']
    assert run(['git','--git-dir=/srv/agent-gates/project.git','rev-parse','main'])==main
    owner('audit','project','verify')
    mark('5 enforced signed orphan recovered at its exact reserved slot without moving main')
    raw=log.read_bytes()
    log.write_bytes(raw.replace(b'"event":"verify"',b'"event":"corrupt"',1))
    result=subprocess.run(['runuser','-u','agent-codex','--','sudo','-n','-u','agent-gates',CLI,'merge','project',a],text=True,capture_output=True)
    assert result.returncode and 'DENY AUDIT_BROKEN:' in result.stderr
    owner('audit','project','reseal','--reason','container Owner reviewed corruption')
    result=subprocess.run([CLI,'accept',v,'--yes'],text=True,capture_output=True)
    assert result.returncode and 'DENY RECEIPT_INVALIDATED:' in result.stderr
    result=subprocess.run(['runuser','-u','agent-codex','--','sudo','-n','-u','agent-gates',CLI,'merge','project',a],text=True,capture_output=True)
    assert result.returncode and 'DENY RECEIPT_INVALIDATED:' in result.stderr
    assert json.loads(gate('status','--all','--json'))[0]['verification']=='INVALIDATED'
    reviewer('verify','project','agent/codex','--no-baseline')
    owner('audit','project','verify')
    assert run(['git','--git-dir=/srv/agent-gates/project.git','rev-parse','main'])==main
    mark('6 enforced reseal invalidates signed evidence and resumes new verification')
    # Exercise exact previous sudoers migration in this existing installation.
    before_key=Path('/var/lib/agent-gates/gate_ed25519').read_bytes()
    before_main=main
    # Replacing current sudoers with exact old policy emulates an existing shared
    # installation; manifests and all code hashes are checked by the upgrader.
    old='''Defaults:%agents env_reset, !setenv
%agents     ALL=(agent-gates) NOPASSWD: /opt/agent-gates/bin/agent-gates verify *, /opt/agent-gates/bin/agent-gates merge *, /opt/agent-gates/bin/agent-gates status *, /opt/agent-gates/bin/gate-receive-pack *
agent-gates ALL=(ag-runner)   NOPASSWD: /opt/agent-gates/bin/ag-run *
'''
    sudoers=Path('/etc/sudoers.d/agent-gates'); sudoers.write_text(old); sudoers.chmod(0o440)
    result=subprocess.run(['/trusted-kit/bin/agent-gates','enforce','init','/tmp/project','--agents','codex,claude,zcode'],text=True,capture_output=True)
    assert result.returncode and ('DENY NOT_ENFORCED:' in result.stderr or 'DENY SUDOERS_CONFLICT:' in result.stderr)
    owner_before=snapshot()
    run(['/trusted-kit/bin/agent-gates','enforce','upgrade','project'])
    assert snapshot()==owner_before and before_key==Path('/var/lib/agent-gates/gate_ed25519').read_bytes()
    assert run(['git','--git-dir=/srv/agent-gates/project.git','rev-parse','main'])==before_main
    gate('history','--json'); run(['visudo','-c'])
    owner('doctor','project')
    mark('upgrade validates policy and preserves refs/receipts/key; init never upgrades differing sudoers')
    print('%s passed, 0 failed' % passed)
except Exception:
    print('%s passed, 1 failed' % passed)
    raise

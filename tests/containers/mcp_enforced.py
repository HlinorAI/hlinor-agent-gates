#!/usr/bin/env python3
"""Real UIDs and sudo, inside a disposable container only; stdio harness, no real clients."""
import fcntl
import hashlib
import importlib.util
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
RECEIPTS=Path('/var/lib/agent-gates/projects/project/receipts')
spec=importlib.util.spec_from_file_location('fixture',Path('/kit/tests/test_mcp.py'))
F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
passed=0


def run(*args):
    p=subprocess.run(args,text=True,capture_output=True);assert p.returncode==0,(args,p.stdout,p.stderr)
    return p.stdout.strip()


def mark(name):
    global passed
    passed+=1;print('PASS '+name,flush=True)


def protected():
    files=[*Path('/opt/agent-gates').rglob('*'),*Path('/etc/sudoers.d').glob('*'),
           Path('/var/lib/agent-gates/gate_ed25519'),Path('/var/lib/agent-gates/gate_ed25519.pub'),
           Path('/etc/agent-gates/owner.pub'),*RECEIPTS.glob('*')]
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files if p.is_file()}


try:
    for agent,project,reason in [('codex','project','INVALID_IDENTITY'),('claude',None,'INVALID_ARGUMENT')]:
        argv=['runuser','-u','agent-claude','--',CLI,'mcp','--agent',agent]
        if project:argv+=['--project',project]
        before=protected()
        p=subprocess.run(argv,input=b'',capture_output=True)
        assert p.returncode==1 and p.stderr.decode().startswith('DENY '+reason+':') and not p.stdout,(p.stdout,p.stderr)
        assert before==protected()
    mark('7 OS identity mismatch and missing enforced project refuse before tools')
    clone='/home/agent-codex/work/project'
    run('runuser','-u','agent-codex','--','bash','-c','cd '+clone+'; echo mcp > feature-mcp; git add feature-mcp; git commit -qm mcp-feature; git push gate agent/codex')
    main=run('git','--git-dir=/srv/agent-gates/project.git','rev-parse','main');before=protected()
    previous=os.environ.get('SUDO_USER');os.environ['SUDO_USER']='forged-owner'
    client=F.Client(CLI,'--project','project',prefix=['runuser','-u','agent-claude','--'])
    try:
        response=client.call('gates_verify',dict(branch='agent/codex'))
        identifier=F.data(response)['receipt_id']
        receipt=json.loads((RECEIPTS/('verification-'+identifier+'.json')).read_bytes())
        assert receipt['verifier']=='agent-claude' and receipt['signature']
        for name in ('gates_status','gates_history','gates_list_agents'):
            response=client.call(name);F.data(response);assert not response['result']['isError']
        assert 'error' in client.call('gates_accept',dict(id=identifier))
    finally:
        client.close()
        if previous is None:os.environ.pop('SUDO_USER',None)
        else:os.environ['SUDO_USER']=previous
    assert all(protected()[name]==value for name,value in before.items())
    assert main==run('git','--git-dir=/srv/agent-gates/project.git','rev-parse','main')
    run(CLI,'audit','project','verify')
    mark('8 verify uses sudo OS identity, signs receipt and preserves protected files/main')
    # Hold the gate lock so the real privileged CLI remains in flight at disconnect.
    with Path('/var/lib/agent-gates/projects/project/locks/gates.lock').open('r+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        client=F.Client(CLI,'--project','project',prefix=['runuser','-u','agent-claude','--'])
        client.send(dict(jsonrpc='2.0',id=999,method='tools/call',params=dict(name='gates_verify',arguments=dict(branch='agent/codex'))))
        deadline=time.monotonic()+5;children=[]
        while not children:
            for path in Path('/proc').glob('[0-9]*/cmdline'):
                try:
                    command=path.read_bytes()
                    if b'agent_gates.py\0verify\0' in command:children.append(int(path.parent.name))
                except (OSError,ProcessLookupError):pass
            assert time.monotonic()<deadline;time.sleep(.02)
        client.close();time.sleep(.3)
        live=[]
        for pid in children:
            path=Path('/proc')/str(pid)/'status'
            if path.exists() and 'State:\tZ' not in path.read_text():live.append(pid)
        assert not live,('privileged CLI survived disconnect',live)
    mark('disconnect kills the real sudo CLI process group')
    run('runuser','-u','agent-codex','--','bash','-c',
        'cd '+clone+'; printf "echo active > /tmp/mcp-runner-active\\nsleep 30\\necho 1 passed\\n" > check.sh; git add check.sh; git commit -qm slow-test; git push gate agent/codex')
    client=F.Client(CLI,'--project','project',prefix=['runuser','-u','agent-claude','--'])
    client.send(dict(jsonrpc='2.0',id=998,method='tools/call',params=dict(name='gates_verify',arguments=dict(branch='agent/codex'))))
    deadline=time.monotonic()+10
    while not Path('/tmp/mcp-runner-active').exists():
        assert time.monotonic()<deadline;time.sleep(.02)
    client.close();time.sleep(.3)
    runner_uid=pwd.getpwnam('ag-runner').pw_uid
    live=[]
    for path in Path('/proc').glob('[0-9]*/status'):
        try:
            text=path.read_text()
            if ('Uid:\t'+str(runner_uid)+'\t') in text and 'State:\tZ' not in text:live.append(path.parent.name)
        except (OSError,ProcessLookupError):pass
    assert not live and not Path('/tmp/mcp-runner-active').exists(),('runner survived disconnect',live)
    assert main==run('git','--git-dir=/srv/agent-gates/project.git','rev-parse','main')
    mark('disconnect during untrusted tests runs existing runner cleanup')
except Exception as exc:
    import traceback;traceback.print_exc();print('FAIL '+repr(exc),flush=True)
    print('%s passed, 1 failed'%passed);sys.exit(1)
print('%s passed, 0 failed'%passed)

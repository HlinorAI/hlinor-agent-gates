#!/usr/bin/env python3
"""No GitHub calls: all gh and publication git subprocesses are fakes in PATH."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

KIT = Path(__file__).resolve().parents[1]
FAKE_GH = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
p=pathlib.Path(os.environ['FAKE_GH_STATE']); s=json.loads(p.read_text())
a=sys.argv[1:]; method=a[a.index('--method')+1]; endpoint=a[a.index('--method')+2]
body=json.load(sys.stdin) if '--input' in a else None
s['calls'].append({'method':method,'endpoint':endpoint,'body':body})
root='repos/HlinorAI/hlinor-agent-gates'; suffix=endpoint.removeprefix(root)
missing=False; result=None
if suffix=='': result={'permissions':{'admin':s.get('admin',True)}}
elif suffix.startswith('/actions/variables'):
    if method=='GET':
        name=suffix.rsplit('/',1)[1]; missing=name not in s['variables']
        result={'name':name,'value':s['variables'].get(name)}
    else:
        s['variables'][body['name']]=body['value']; result=body
elif suffix.startswith('/commits/main/check-runs'):
    result=[{'check_runs':[{'name':n} for n in s['ci']]}]
elif suffix=='/branches/main/protection':
    if method=='PUT':
        b=body.copy()
        b['enforce_admins']={'enabled':body['enforce_admins']}
        for field in ('allow_force_pushes','allow_deletions','required_linear_history',
                      'required_conversation_resolution','block_creations','lock_branch','allow_fork_syncing'):
            if field in b: b[field]={'enabled':b[field]}
        if b.get('restrictions'):
            b['restrictions']={k:[{'login' if k=='users' else 'slug':name} for name in names]
                               for k,names in b['restrictions'].items()}
        s['protection']=b
    result=s.get('protection'); missing=result is None
elif suffix.startswith('/issues?'): result=[s['issues']]
elif suffix=='/issues' and method=='POST':
    s['issues'].append({**body,'number':len(s['issues'])+1}); result=s['issues'][-1]
elif suffix.startswith('/issues/') and method=='PATCH':
    result=next(i for i in s['issues'] if i['number']==int(suffix.rsplit('/',1)[1])); result.update(body)
else: raise AssertionError((method,endpoint,body))
p.write_text(json.dumps(s))
if missing:
    print('gh: Not Found (HTTP 404)',file=sys.stderr); sys.exit(1)
if result is not None: print(json.dumps(result))
'''
FAKE_GIT = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args=sys.argv[1:]; log=pathlib.Path(os.environ['FAKE_GIT_LOG'])
with log.open('a') as f: f.write(json.dumps(args)+'\n')
# Skip options supplied by the stdlib attestation helper.
a=args[:]
while a and a[0] in ('-c','-C'): a=a[2:]
old='1'*40; new='2'*40
cmd=a[0]
if cmd=='branch': print('main')
elif cmd=='status': pass
elif cmd=='remote': print('fixture-origin')
elif cmd=='ls-remote': print('3'*40+'\t'+a[-1])
elif cmd=='fetch':
    pathlib.Path(os.environ['FAKE_FETCH_HEAD']).write_text(old if a[1]=='origin' and a[2]=='refs/heads/main' else new)
elif cmd=='rev-parse':
    ref=a[-1]
    if ref=='FETCH_HEAD': print(pathlib.Path(os.environ['FAKE_FETCH_HEAD']).read_text())
    elif ref.startswith('1'): print(old)
    else: print(new)
elif cmd=='merge': pass
elif cmd=='merge-base': pass
elif cmd=='rev-list': print(new)
elif cmd=='log': print(new[:7]+' Owner change')
elif cmd=='show': print('Owner change')
elif cmd=='hash-object': sys.stdin.read(); print('3'*40)
elif cmd=='notes': pass
elif cmd=='show-ref': pass
elif cmd=='push':
    assert '--atomic' in a and 'origin' in a
    assert new+':refs/heads/main' in a
    assert 'refs/notes/agent-gates' in a and 'refs/notes/agent-gates-publish' in a
else: raise AssertionError(a)
'''


def run(args, env, data=None, ok=True):
    result = subprocess.run([str(a) for a in args], input=data, capture_output=True, env=env)
    if ok:
        assert result.returncode == 0, result.stdout.decode() + result.stderr.decode()
    return result


passed = failed = 0
with tempfile.TemporaryDirectory(prefix='agent-gates-tools-') as temp:
    temp = Path(temp)
    fake = temp / 'fake'; fake.mkdir()
    for name, source in (('gh', FAKE_GH), ('git', FAKE_GIT)):
        (fake / name).write_text(source); (fake / name).chmod(0o755)
    env = {**os.environ, 'PATH': str(fake) + os.pathsep + os.environ['PATH'],
           'FAKE_GH_STATE': str(temp / 'state'), 'FAKE_GIT_LOG': str(temp / 'git.log'),
           'FAKE_FETCH_HEAD': str(temp / 'fetch')}
    for name in ('owner', 'other', 'accept'):
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(temp/name)],check=True)
    state = temp / 'state'
    def reset():
        state.write_text(json.dumps({'variables':{},'ci':['test (ubuntu-latest)','test (macos-latest)','enforced'],
                                    'protection':None,'issues':[],'calls':[]}))
    def read(): return json.loads(state.read_text())
    def settings():
        s=read(); return s['variables'],s['protection'],s['issues']
    protect=[KIT/'bin/agent-gates','github','protect','--owner-key',temp/'owner.pub',
             '--accept-keys',temp/'accept.pub']
    def t10():
        reset(); run(protect,env); first=settings(); run(protect,env); assert settings()==first
        required=read()['protection']['required_status_checks']['checks']
        assert {v['context'] for v in required}=={'test (ubuntu-latest)','test (macos-latest)','enforced','agent-gates/verify'}
        assert read()['protection']['allow_force_pushes']=={'enabled':False}
        assert read()['protection']['allow_deletions']=={'enabled':False}
        before=settings(); count=len(read()['calls'])
        result=run([KIT/'bin/agent-gates','github','protect','--owner-key',temp/'other.pub'],env,ok=False)
        assert result.returncode==1 and result.stdout.startswith(b'DENY OWNER_KEY_CHANGED:')
        assert settings()==before and all(c['method']=='GET' for c in read()['calls'][count:])
    def rotation():
        reset(); run(protect,env)
        spec=importlib.util.spec_from_file_location('check',KIT/'bin/github_verify.py')
        check=importlib.util.module_from_spec(spec); spec.loader.exec_module(check)
        old=read()['variables']['AGENT_GATES_OWNER_KEY']
        new=' '.join((temp/'other.pub').read_text().split()[:2])
        payload={'kind':'owner-key-rotation','schema':1,'repo':'HlinorAI/hlinor-agent-gates',
                 'old_key':old,'new_key':new,'signature':None}
        signature=subprocess.run(['ssh-keygen','-Y','sign','-f',str(temp/'owner'),'-n','agent-gates-publish'],
                                 input=check.payload(payload),capture_output=True,check=True).stdout
        (temp/'rotation.sig').write_bytes(signature)
        run([KIT/'bin/agent-gates','github','protect','--owner-key',temp/'other.pub','--rotate',
             '--rotation-signature',temp/'rotation.sig'],env)
        assert read()['variables']['AGENT_GATES_OWNER_KEY']==new
    def admin_missing_ci():
        for field,value,code in [('admin',False,'ADMIN_REQUIRED'),('ci',[],'CI_CHECKS_MISSING')]:
            reset(); s=read(); s[field]=value; state.write_text(json.dumps(s))
            result=run(protect,env,ok=False)
            assert result.returncode==1 and b'DENY '+code.encode()+b':' in result.stdout
            assert not read()['variables'] and read()['protection'] is None
    def issue():
        reset()
        # Simulate a completed failed check without executing any untrusted artifact.
        args=[sys.executable,'-IB',KIT/'bin/github_issue.py','--repository','HlinorAI/hlinor-agent-gates','--run-url']
        run(args+['https://example.invalid/runs/1'],env)
        run(args+['https://example.invalid/runs/2'],env)
        assert len(read()['issues'])==1
        assert read()['issues'][0]['title']=='agent-gates: main is unverified'
        assert 'runs/2' in read()['issues'][0]['body']
    def publication():
        # Fake Git records the intended effect. No remote is created, no real push occurs.
        args=['bash',KIT/'scripts/publish.sh','--source','fixture-source','--key',temp/'owner']
        run(args,env,data=b'n\n',ok=False)
        calls=[json.loads(line) for line in (temp/'git.log').read_text().splitlines()]
        assert not any(a[0]=='push' for a in calls)
        (temp/'git.log').write_text('')
        run(args,env,data=b'y\n')
        calls=[json.loads(line) for line in (temp/'git.log').read_text().splitlines()]
        pushes=[a for a in calls if a[0]=='push']
        assert len(pushes)==1
        assert any('agent-gates-publish' in ' '.join(a) for a in calls)
    for name,test in [('10 idempotent protection and foreign key denial',t10),('signed explicit key rotation',rotation),
                      ('admin and missing CI fail before writes',admin_missing_ci),
                      ('failure opens one issue and updates it',issue),('confirmed atomic publication via fake git',publication)]:
        try:
            test(); passed+=1; print('PASS '+name,flush=True)
        except Exception as exc:
            failed+=1; print('FAIL '+name+': '+str(exc),flush=True)
print(f'{passed} passed, {failed} failed')
sys.exit(bool(failed))

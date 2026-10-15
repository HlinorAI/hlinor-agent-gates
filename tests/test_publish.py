#!/usr/bin/env python3
"""v0.7 tests 9–12: real local merges and signed notes; network calls are faked."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

KIT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module
F = load('audit_fixture', KIT/'tests/test_observability.py')
C = load('checker', KIT/'bin/github_verify.py')
NAME = 'HlinorAI/test'


def prepare(f, mode=None, after_first=None):
    for name in ('accept', 'publish', 'rotated'):
        result = F.command(['ssh-keygen','-q','-t','ed25519','-N','','-f', f.root/name])
        assert result.returncode == 0, result.stderr
    (f.repo/'.agent-gates/allowed_signers').write_text('owner '+(f.root/'accept.pub').read_text())
    with (f.repo/'.agent-gates/config').open('a') as stream:
        stream.write('OWNER_SIGNING_KEY="'+str(f.root/'accept')+'"\n')
        if mode is not None: stream.write('AUDIT_PUBLISH='+mode+'\n')
    f.git('add','.'); f.git('commit','-qm','Owner signed acceptance policy')
    f.old = f.git('rev-parse','main'); f.merges = []
    for name in ('codex','claude'):
        f.branch(name); v=f.verify(name); a=f.accept(v); f.call('merge',a)
        f.merges.append(f.git('rev-parse','main'))
        if len(f.merges) == 1 and after_first is not None: after_first(f)
    f.new = f.merges[-1]
    return C.attest(f.repo,f.old,f.new,f.root/'publish',NAME)


def store(f, ref, commit, record):
    blob=C.git(f.repo,'hash-object','-w','--stdin',data=C.canonical(record)).decode().strip()
    C.git(f.repo,'notes','--ref='+ref,'add','-f','-C',blob,commit)


def signed(f, record, key='publish'):
    record=copy.deepcopy(record)
    result=subprocess.run(['ssh-keygen','-Y','sign','-f',str(f.root/key),'-n','agent-gates-publish'],
                          input=C.payload(record),capture_output=True,check=True)
    record['signature']=result.stdout.decode()
    return record


def action(f, ok, error=None, before=None, key='publish'):
    main=f.git('rev-parse','main')
    result=subprocess.run([sys.executable,'-IB',str(KIT/'bin/github_verify.py'),'--repo',str(f.repo),
        '--event','push','--before',before or f.old,'--after',f.new,'--repository',NAME,
        '--output',str(f.root/'report')],capture_output=True,
        env={**os.environ,'AGENT_GATES_OWNER_KEY':(f.root/(key+'.pub')).read_text(),
             'AGENT_GATES_ACCEPT_KEYS':(f.root/'accept.pub').read_text()})
    report=json.loads((f.root/'report/result.json').read_text())
    assert (result.returncode == 0) == ok, result.stdout.decode()+result.stderr.decode()
    assert report['ok'] == ok
    if error: assert error in report['error'],report
    assert f.git('rev-parse','main') == main
    return report


def head(f):
    record=prepare(f)
    assert record['audit_publish']=='head' and 'audit_chain' not in record
    assert record['audit_head']==dict(seq=len(f.rows()),hash=f.head())
    assert len(f.merges)==2
    assert len(action(f,True)['rows'])==2


def order(f):
    record=prepare(f)
    # Preserve all receipt signatures and bindings; re-sign a smaller advertised head.
    bad=copy.deepcopy(record); bad['audit_head']['seq']=1
    store(f,C.PUBLISH,f.new,signed(f,bad));action(f,False,'sequence out of range')
    store(f,C.PUBLISH,f.new,record)
    bundles={commit:C.note(f.repo,C.RECEIPTS,commit) for commit in f.merges}
    # Isolate the ordering check with otherwise well-formed anchors.
    bad=copy.deepcopy(bundles)
    bad[f.new]['verification']['audit_seq']=bad[f.merges[0]]['merge']['audit_seq']
    try:C.check_head_attestation(record,bad,f.merges)
    except C.Invalid as exc: assert 'ordering' in str(exc)
    else:raise AssertionError('inter-bundle order accepted')
    bundle=copy.deepcopy(bundles[f.new])
    bundle['merge']['audit_seq']=bundle['verification']['audit_seq']
    bundle['merge']['id']=C.identifier(bundle['merge'])
    store(f,C.RECEIPTS,f.new,bundle);action(f,False,'ordering')


def duplicate(f):
    record=prepare(f)
    bundles={commit:C.note(f.repo,C.RECEIPTS,commit) for commit in f.merges}
    # The first repeated receipt is checked before sequence ordering.
    bad=copy.deepcopy(bundles)
    bad[f.new]['verification']=bad[f.merges[0]]['verification']
    try:C.check_head_attestation(record,bad,f.merges)
    except C.Invalid as exc: assert 'reused' in str(exc)
    else:raise AssertionError('duplicate receipt accepted')
    store(f,C.RECEIPTS,f.new,bad[f.new]);action(f,False)


def rollback(f):
    def truncate_after_checkpoint(f):
        path=f.receipts/'audit.jsonl'
        original=path.read_bytes()
        for _ in range(10):
            f.deny('SELF_VERIFICATION','verify','agent/codex','--as','codex')
        checkpoint=C.attest(f.repo,f.old,f.merges[0],f.root/'publish',NAME)
        assert checkpoint['audit_head']['seq']==13
        # Restore only the first three real events, losing a published DENY tail.
        # No receipt anchors are lost; a new valid verification can now reuse seq 4.
        path.write_bytes(original)
        f.call('audit','verify')
    record=prepare(f,after_first=truncate_after_checkpoint)
    assert record['audit_head']['seq']==6
    current=copy.deepcopy(record); current.update(old_main=f.merges[0],commits=[f.new])
    store(f,C.PUBLISH,f.new,signed(f,current))
    action(f,False,'decreased',before=f.merges[0])
    # Simulate the trusted workflow_run notification only after the actual red check.
    fake=f.root/'fake';fake.mkdir();log=f.root/'gh.jsonl'
    gh=fake/'gh';gh.write_text('''#!/usr/bin/env python3
import json,os,sys
args=sys.argv[1:]
with open(os.environ['FAKE_GH_LOG'],'a') as stream:
 stream.write(json.dumps({'args':args,'body':json.load(sys.stdin) if '--input' in args else None})+'\\n')
print('[[]]' if '--paginate' in args else '{}')
''');gh.chmod(0o755)
    result=subprocess.run([sys.executable,'-IB',str(KIT/'bin/github_issue.py'),'--repository',NAME,
         '--run-url','https://example.invalid/failed-publish'],capture_output=True,
         env={**os.environ,'PATH':str(fake)+os.pathsep+os.environ['PATH'],'FAKE_GH_LOG':str(log)})
    assert result.returncode==0,result.stderr.decode()
    calls=[json.loads(line) for line in log.read_text().splitlines()]
    assert any('POST' in call['args'] and call['body']['title']=='agent-gates: main is unverified' for call in calls)


def rotation(f):
    record=prepare(f)
    prior=copy.deepcopy(record);prior.update(new_main=f.merges[0],commits=[f.merges[0]])
    prior['audit_head']['seq']=3
    store(f,C.PUBLISH,f.merges[0],signed(f,prior))
    current=copy.deepcopy(record);current.update(old_main=f.merges[0],commits=[f.new])
    store(f,C.PUBLISH,f.new,signed(f,current,'rotated'))
    action(f,False,'trusted key',before=f.merges[0],key='rotated')
    store(f,C.PUBLISH,f.merges[0],signed(f,prior,'rotated'))
    action(f,True,before=f.merges[0],key='rotated')


def chain(f):
    record=prepare(f,'chain')
    assert record['audit_publish']=='chain' and record['audit_chain']==f.rows()
    action(f,True)
    bad=copy.deepcopy(record);bad['audit_chain'][0]['prev']='f'*64
    store(f,C.PUBLISH,f.new,signed(f,bad));action(f,False,'predecessor')


for label,fn in [('9 head default, two real gate merges, no audit rows',head),
                 ('10 out-of-order and out-of-range anchors',order),
                 ('10 repeated receipt in two bundles',duplicate),
                 ('11 rollback red and fake issue opened',rollback),
                 ('checkpoint key rotation requires Owner re-signing',rotation),
                 ('12 chain mode preserves full-chain verification',chain)]:
    F.case(label,fn)
print(f'{F.passed} passed, {F.failed} failed')
sys.exit(bool(F.failed))

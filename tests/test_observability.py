#!/usr/bin/env python3
"""Phase A observable CLI regressions; only temporary repositories, no network."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile

KIT = Path(__file__).resolve().parents[1]
passed = failed = 0


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def command(args, cwd=None, uid=None):
    def identity():
        os.setgroups([]); os.setgid(uid); os.setuid(uid)
    result = subprocess.run([str(x) for x in args], cwd=cwd, text=True, capture_output=True,
                            env={**os.environ, 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1',
                                 'PYTHONDONTWRITEBYTECODE': '1'},
                            preexec_fn=identity if uid is not None else None)
    return result


class Fixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='agent-gates-audit-')
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'; self.repo.mkdir()
        self.git('init','-q','-b','main')
        self.git('config','user.name','test'); self.git('config','user.email','test@local')
        gate = self.repo/'.agent-gates'; gate.mkdir()
        for name in ('agent-gates','agent_gates.py'):
            shutil.copyfile(KIT/'bin'/name, gate/name)
        (gate/'agent-gates').chmod(0o755)
        (gate/'config').write_text('MAIN_BRANCH=main\nTEST_CMD="bash check.sh"\nOWNER_NAME=owner\nOWNER_SIGNING_KEY=""\nACCEPT_TTL_HOURS=24\n')
        (self.repo/'check.sh').write_text('echo 1 passed\n')
        self.git('add','.'); self.git('commit','-qm','initial')
        self.cli = gate/'agent-gates'
        self.receipts=self.repo/'.git/agent-gates/receipts'
        self.uid=None

    def close(self):
        self.temp.cleanup()

    def git(self,*args):
        r=command(['git','-C',self.repo,*args]); assert r.returncode==0, r.stderr
        return r.stdout.strip()

    def branch(self,name='codex',fail=False):
        self.git('checkout','-q','-b','agent/'+name)
        (self.repo/'feature').write_text(name)
        if fail: (self.repo/'check.sh').write_text('exit 1\n')
        self.git('add','.'); self.git('commit','-qm','feature')
        self.git('checkout','-q','main')

    def call(self,*args,code=0):
        result=command([self.cli,*args],uid=self.uid)
        assert result.returncode==code, (args,result.stdout,result.stderr)
        return result.stdout.strip()

    def deny(self,reason,*args):
        main=self.git('rev-parse','main')
        out=self.call(*args,code=1)
        assert out.startswith('DENY '+reason+':'),out
        assert self.git('rev-parse','main')==main
        return out

    def verify(self,name='codex'):
        return self.call('verify','agent/'+name,'--as','reviewer','--no-baseline').splitlines()[-1]

    def accept(self,v):
        return self.call('accept',v,'--yes').splitlines()[-1]

    def read(self,kind,identifier):
        return json.loads((self.receipts/(kind+'-'+identifier+'.json')).read_bytes())

    def rows(self):
        return [json.loads(line) for line in (self.receipts/'audit.jsonl').read_bytes().splitlines()]

    def head(self):
        return self.rows()[-1]['hash']


def case(label,fn):
    global passed,failed
    f=Fixture()
    try:
        fn(f); passed+=1; print('PASS '+label,flush=True)
    except Exception as exc:
        failed+=1; print('FAIL '+label+': '+repr(exc),flush=True)
    finally:
        f.close()


def states(f):
    f.branch(); v=f.verify(); f.accept(v)
    f.git('checkout','-q','agent/codex'); (f.repo/'later').write_text('later'); f.git('add','.'); f.git('commit','-qm','later'); f.git('checkout','-q','main')
    f.branch('claude',fail=True); f.verify('claude')
    f.branch('zcode'); v=f.verify('zcode'); f.accept(v)
    rows={r['branch']:r for r in json.loads(f.call('status','--all','--json'))}
    assert rows['agent/codex']['verification']=='STALE: BRANCH_MOVED'
    assert rows['agent/claude']['verification']=='REJECT'
    assert rows['agent/zcode']['acceptance'].startswith('VALID') and rows['agent/zcode']['next_step']=='merge'
    assert rows['agent/codex']['next_step']=='re-verify'
    assert len(json.loads(f.call('list-agents','--json')))==3
    (f.repo/'main-only').write_text('main'); f.git('add','.'); f.git('commit','-qm','main moved')
    rows={r['branch']:r for r in json.loads(f.call('status','--all','--json'))}
    assert rows['agent/codex']['verification']=='STALE: BRANCH_MOVED'
    assert rows['agent/zcode']['verification']=='STALE: MAIN_MOVED'


def flow(f):
    f.branch(); v=f.verify(); a=f.accept(v); m=f.call('merge',a)
    f.deny('RECEIPT_REUSED','merge',a)
    rows=f.rows(); assert [r['event'] for r in rows]==['verify','accept','merge','deny']
    for kind,ident in [('verification',v),('acceptance',a),('merge',m)]:
        record=f.read(kind,ident); row=rows[record['audit_seq']-1]
        assert record['audit_prev']==row['prev'] and row['receipt']==ident
    assert f.call('audit','verify').startswith('OK 4 ')
    summary=json.loads(f.call('status','--all','--json'))[0]
    assert summary['verification']=='MERGED' and summary['acceptance']=='USED'
    before={p.name:p.read_bytes() for p in f.receipts.iterdir() if p.is_file()}
    assert len(json.loads(f.call('history','--since','7d','--branch','agent/codex','--json')))>=3
    f.call('list-agents','--json'); f.call('status','--all','--json'); f.call('audit','verify')
    assert before=={p.name:p.read_bytes() for p in f.receipts.iterdir() if p.is_file()}


def inner(f):
    f.branch(); v=f.verify(); a=f.accept(v); f.deny('SELF_VERIFICATION','verify','agent/codex','--as','codex')
    log=f.receipts/'audit.jsonl'; original=log.read_bytes(); lines=original.splitlines(keepends=True)
    variations=[lines[:1]+[lines[1].replace(b'"OK"',b'"BAD"')]+lines[2:], lines[:1]+lines[2:], [lines[1],lines[0],*lines[2:]]]
    for replacement in variations:
        log.write_bytes(b''.join(replacement))
        out=f.deny('AUDIT_BROKEN','audit','verify'); assert 'seq ' in out
        f.deny('AUDIT_BROKEN','verify','agent/codex','--as','reviewer')
        f.deny('AUDIT_BROKEN','accept',v,'--yes'); f.deny('AUDIT_BROKEN','merge',a)
        before=log.read_bytes(); f.call('history','--json'); assert log.read_bytes()==before
        log.write_bytes(original)


def tail(f):
    f.branch(); f.verify()
    log=f.receipts/'audit.jsonl'; head=f.head(); log.write_bytes(b'')
    f.deny('AUDIT_BROKEN','audit','verify'); f.deny('AUDIT_BROKEN','audit','verify','--expect-head',head)
    f.deny('AUDIT_BROKEN','audit','verify','--expect-seq','1')
    f.verify(); assert f.rows()[0]['event']=='recovered' and f.rows()[0]['seq']==1
    f.call('audit','verify')
    f.deny('SELF_VERIFICATION','verify','agent/codex','--as','codex')
    rows=f.rows(); head=rows[-1]['hash']; seq=len(rows)
    log.write_bytes(b''.join(canon(row)+b'\n' for row in rows[:-1]))
    assert f.call('audit','verify').startswith('OK')  # receipt-less tail needs an external anchor
    f.deny('AUDIT_BROKEN','audit','verify','--expect-head',head)
    f.deny('AUDIT_BROKEN','audit','verify','--expect-seq',str(seq))


def fault(f,merge=False):
    f.branch(); v=f.verify(); a=f.accept(v) if merge else None
    if os.geteuid()==0:
        f.uid=pwd.getpwnam('nobody').pw_uid
        for base,dirs,files in os.walk(f.root):
            os.chown(base,f.uid,f.uid)
            for name in files: os.chown(Path(base)/name,f.uid,f.uid)
    log=f.receipts/'audit.jsonl'; log.chmod(0o400)
    args=('merge',a) if merge else ('verify','agent/codex','--as','reviewer','--no-baseline')
    # Merge may already have updated main, but success must never be reported.
    out=f.call(*args,code=1); assert out.startswith('DENY AUDIT_UNAVAILABLE:'),out
    missing=[p for p in f.receipts.glob('*.json') if json.loads(p.read_bytes()).get('audit_seq')==len(f.rows())+1]
    assert len(missing)==1
    original=json.loads(missing[0].read_bytes()); seq=original['audit_seq']
    log.chmod(0o600)
    f.verify()
    row=f.rows()[seq-1]
    assert row['event']=='recovered' and row['receipt']==original['id'] and row['prev']==original['audit_prev']
    f.call('audit','verify')


def reseal(f):
    f.branch(); v=f.verify(); a=f.accept(v)
    log=f.receipts/'audit.jsonl'; raw=log.read_bytes()
    log.write_bytes(raw.replace(b'"event":"verify"',b'"event":"forged"',1))
    f.deny('AUDIT_BROKEN','verify','agent/codex','--as','reviewer')
    f.call('audit','reseal','--reason','Owner reviewed corrupted log')
    row=f.rows()[0]; assert row['event']=='reseal' and set(row['invalidated_receipts'])=={v,a}
    assert (f.receipts/row['discarded_tail_file']).read_bytes()==log_before(raw)
    f.deny('RECEIPT_INVALIDATED','accept',v,'--yes'); f.deny('RECEIPT_INVALIDATED','merge',a)
    summary=json.loads(f.call('status','--all','--json'))[0]
    assert summary['verification']==summary['acceptance']=='INVALIDATED'
    new=f.verify(); assert f.read('verification',new)['audit_seq']==4
    f.call('audit','verify')


def log_before(raw):
    return raw.replace(b'"event":"verify"',b'"event":"forged"',1)


def collision(f):
    f.branch(); v=f.verify(); record=f.read('verification',v)
    record['created_at']='2099-01-01T00:00:00Z'; record.pop('id'); record['id']=hashlib.sha256(canon(record)).hexdigest()[:12]
    (f.receipts/('verification-'+record['id']+'.json')).write_bytes(canon(record))
    f.deny('AUDIT_BROKEN','verify','agent/codex','--as','reviewer')


def checks(f):
    f.branch(); v=f.verify(); a=f.accept(v)
    for reason,ident in [('RECEIPT_TAMPERED','bad'),('RECEIPT_TAMPERED','0'*12)]:
        before={p.name:p.read_bytes() for p in f.receipts.glob('*.json')}; main=f.git('rev-parse','main')
        checked=f.deny(reason,'check-merge',ident); merged=f.deny(reason,'merge',ident)
        assert checked==merged and main==f.git('rev-parse','main')
        assert before=={p.name:p.read_bytes() for p in f.receipts.glob('*.json')}
    f.git('checkout','-q','agent/codex'); (f.repo/'later').write_text('later'); f.git('add','.');f.git('commit','-qm','move');f.git('checkout','-q','main')
    assert f.deny('BRANCH_MOVED','check-merge',a)==f.deny('BRANCH_MOVED','merge',a)
    # Restoring only the test branch is a fixture operation, never product behavior.
    f.git('update-ref','refs/heads/agent/codex',f.read('verification',v)['head_sha'])
    (f.repo/'dirty').write_text('dirty')
    assert f.deny('MAIN_DIRTY','check-merge',a)==f.deny('MAIN_DIRTY','merge',a)
    (f.repo/'dirty').unlink()
    f.call('merge',a)
    assert f.deny('RECEIPT_REUSED','check-merge',a)==f.deny('RECEIPT_REUSED','merge',a)


def first_reads(f):
    state=f.repo/'.git/agent-gates'
    assert not state.exists()
    f.call('status','--all','--json'); f.call('history','--json')
    f.call('list-agents','--json'); assert f.call('audit','verify').startswith('OK 0 ')
    assert not state.exists()


def unreadable_reseal(f):
    f.branch(); v=f.verify()
    receipt=f.receipts/('verification-'+v+'.json')
    receipt.write_text('{broken JSON')
    before=receipt.read_bytes(); main=f.git('rev-parse','main')
    f.call('audit','reseal','--reason','unreadable evidence')
    row=f.rows()[-1]
    assert v in row['invalidated_receipts']
    assert row['unreadable_receipts']==[dict(id=v,file=receipt.name,reason='unreadable')]
    assert receipt.read_bytes()==before and f.git('rev-parse','main')==main
    assert f.call('audit','verify').startswith('OK ')
    # Evidence is never recovered, and new valid receipts can follow reseal.
    f.verify(); assert f.call('audit','verify').startswith('OK ')


def actual_actor(f):
    previous=os.environ.get('USER')
    os.environ['USER']='forged-owner'
    try:
        f.branch(); v=f.verify(); a=f.accept(v); m=f.call('merge',a)
        assert f.read('merge',m)['merged_by']==pwd.getpwuid(os.getuid()).pw_name
        f.deny('RECEIPT_TAMPERED','merge','bad')
        assert f.rows()[-1]['actor']==pwd.getpwuid(os.getuid()).pw_name
    finally:
        if previous is None: os.environ.pop('USER',None)
        else: os.environ['USER']=previous


if __name__=='__main__':
    case('initial read-only commands never initialize state',first_reads)
    case('1 branch status precedence and list agents',states)
    case('3 event order, receipt anchors, merged/used states and read-only paths',flow)
    case('4a inner edit/delete/reorder breaks chain and blocks mutations',inner)
    case('4b receipt tail, external anchors and exact-slot recovery',tail)
    case('5 verify append failure and recovery',lambda f:fault(f))
    case('5 merge append failure and recovery',lambda f:fault(f,True))
    case('6 reseal preserves evidence, invalidates by IDs and resumes chain',reseal)
    case('recovery collision fails closed without moving main',collision)
    case('11 five matching check-merge/merge DENYs with unchanged receipts',checks)
    case('review malformed receipt reseal preserves unreadable evidence',unreadable_reseal)
    case('review cooperative actor ignores forged USER',actual_actor)
    print('%s passed, %s failed' % (passed,failed))
    sys.exit(bool(failed))

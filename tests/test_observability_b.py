#!/usr/bin/env python3
"""Phase B, temporary repositories and fake hooks only."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time

KIT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fixtures',KIT/'tests/test_observability.py')
F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
passed=failed=0


def config(f,extra):
    path=f.repo/'.agent-gates/config';path.write_text(path.read_text()+extra)
    f.git('add','.');f.git('commit','-qm','Owner configuration')


def case(name,fn):
    global passed,failed
    f=F.Fixture()
    try:fn(f);passed+=1;print('PASS '+name,flush=True)
    except Exception as exc:failed+=1;print('FAIL '+name+': '+repr(exc),flush=True)
    finally:f.close()


def dedupe(f):
    log=f.root/'notifications.jsonl'
    hook=f.root/'notify.py';hook.write_text('import sys,json\nfrom pathlib import Path\np=json.load(sys.stdin)\nwith Path('+repr(str(log))+').open("a") as out: out.write(json.dumps(p)+"\\n")\n')
    config(f,'ACCEPT_TTL_HOURS=1\nNOTIFY_EVENTS=expiring\nNOTIFY_CMD="/usr/bin/python3 '+str(hook)+'"\n')
    f.branch();v=f.verify();a=f.accept(v)
    main=f.git('rev-parse','main')
    for _ in range(2):f.call('status','--all','--notify','--json')
    messages=[json.loads(line) for line in log.read_text().splitlines()]
    assert len(messages)==1 and messages[0]['event']=='expiring' and messages[0]['receipt']==a and '\n' not in messages[0]['text']
    assert len([r for r in f.rows() if r['event']=='expiring'])==1
    assert f.git('rev-parse','main')==main;f.call('audit','verify')


def failed_hook(f,hang=False):
    config(f,'NOTIFY_EVENTS=verify\nNOTIFY_CMD="'+('sleep 30' if hang else 'exit 1')+'"\n')
    f.branch();main=f.git('rev-parse','main');start=time.monotonic();v=f.verify()
    assert f.read('verification',v)['verdict']=='ACCEPT'
    rows=f.rows();assert [r['event'] for r in rows]==['verify','notify_failed']
    assert f.git('rev-parse','main')==main
    assert time.monotonic()-start < 15
    f.call('audit','verify')


def worktree(f):
    f.branch();v=f.verify()
    path=f.root/'author';f.git('worktree','add',str(path),'agent/codex')
    return path,v


def dirty(f):
    path,v=worktree(f);(path/'dirty').write_text('keep')
    before=(f.receipts/('verification-'+v+'.json')).read_bytes()
    f.deny('DIRTY_WORKTREE','remove-agent','codex','--yes')
    assert (path/'dirty').read_text()=='keep' and (f.receipts/('verification-'+v+'.json')).read_bytes()==before


def remove(f):
    path,v=worktree(f);branch=f.git('rev-parse','agent/codex');main=f.git('rev-parse','main')
    before={p.name:p.read_bytes() for p in f.receipts.glob('*.json')}
    assert 'REMOVED codex' in f.call('remove-agent','codex','--yes')
    assert not path.exists() and f.git('rev-parse','agent/codex')==branch
    assert f.call('remove-agent','codex','--yes')=='ALREADY REMOVED'
    assert before=={p.name:p.read_bytes() for p in f.receipts.glob('*.json')} and f.git('rev-parse','main')==main


def cleanup(f):
    path,v=worktree(f);root=f.receipts.parent/'tmp';root.mkdir(exist_ok=True)
    locks=f.receipts.parent/'locks';locks.mkdir(exist_ok=True)
    tokens=['a'*32,'b'*32]
    for token in tokens:
        checkout=root/token/'checkout';checkout.parent.mkdir()
        f.git('worktree','add','--detach',str(checkout),'main')
        (root/(token+'.json')).write_text(json.dumps(dict(token=token,kind='worktree')))
    pending=f.repo/'.git/agent-gates-pending';pending.write_text('keep')
    foreign=root/'foreign';foreign.mkdir();(foreign/'keep').write_text('keep')
    main=f.git('rev-parse','main');before={p.name:p.read_bytes() for p in f.receipts.iterdir() if p.is_file()}
    with (locks/('temp-'+tokens[1]+'.lock')).open('a+') as held:
        fcntl.flock(held,fcntl.LOCK_EX)
        f.call('cleanup','--dry-run');assert all((root/t).exists() for t in tokens)
        assert before=={p.name:p.read_bytes() for p in f.receipts.iterdir() if p.is_file()}
        f.call('cleanup');assert not (root/tokens[0]).exists() and (root/tokens[1]).exists()
    assert (locks/('temp-'+tokens[1]+'.lock')).exists() and pending.read_text()=='keep' and path.exists() and foreign.exists()
    assert main==f.git('rev-parse','main') and all((f.receipts/n).read_bytes()==data for n,data in before.items() if n!='audit.jsonl')


def export_waits(f):
    config(f,'TEST_CMD="sleep 2; echo passed"\n');f.branch()
    process=subprocess.Popen([str(f.cli),'verify','agent/codex','--as','reviewer','--no-baseline'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    deadline=time.monotonic()+10
    while not list((f.receipts.parent/'tmp').glob('*.json')):
        assert time.monotonic()<deadline;time.sleep(.01)
    started=time.monotonic();target=f.root/'export.tar.gz'
    f.call('export-audit',str(target));assert time.monotonic()-started>1
    out,err=process.communicate(timeout=10);assert process.returncode==0,(out,err)
    with tarfile.open(target) as archive:files={m.name:archive.extractfile(m).read() for m in archive.getmembers()}
    manifest=json.loads(files.pop('MANIFEST.json'))
    assert manifest['files']=={n:hashlib.sha256(data).hexdigest() for n,data in files.items()}
    rows=[json.loads(line) for line in files['audit.jsonl'].splitlines()]
    assert manifest['seq']==len(rows) and manifest['head']==f.head()==rows[-1]['hash']
    assert f.call('audit','verify').startswith('OK '+str(manifest['seq'])+' '+manifest['head'])


def attestation(f):
    source=KIT/'bin/github_verify.py'
    spec=importlib.util.spec_from_file_location('checker',source);C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
    for name in ('accept','publish'):F.command(['ssh-keygen','-q','-t','ed25519','-N','','-f',f.root/name])
    allowed=f.repo/'.agent-gates/allowed_signers';allowed.write_text('owner '+(f.root/'accept.pub').read_text())
    config(f,'AUDIT_PUBLISH=chain\nOWNER_SIGNING_KEY="'+str(f.root/'accept')+'"\n')
    base=f.git('rev-parse','main');f.branch();v=f.verify();a=f.accept(v);m=f.call('merge',a);head=f.git('rev-parse','main')
    export=f.root/'export.tar.gz';f.call('export-audit',str(export))
    # Publication checkout has notes, but no server receipts or audit state.
    clone=f.root/'publication';F.command(['git','clone','-q',f.repo,clone]);F.command(['git','-C',clone,'config','user.name','owner']);F.command(['git','-C',clone,'config','user.email','owner@local'])
    F.command(['git','-C',clone,'fetch','-q',f.repo,'refs/notes/agent-gates:refs/notes/agent-gates'])
    record=C.attest(clone,base,head,f.root/'publish','HlinorAI/test',export)
    assert record['audit_head']==dict(seq=len(f.rows()),hash=f.head())
    owner=(f.root/'publish.pub').read_text();accept=(f.root/'accept.pub').read_text()
    C.check(clone,'push',base,head,owner,'HlinorAI/test',accept_keys=accept)
    bundle=C.note(clone,C.RECEIPTS,head)
    forged=json.loads(json.dumps(bundle))
    forged['merge']['audit_seq']=forged['verification']['audit_seq']
    forged['merge']['audit_prev']=forged['verification']['audit_prev']
    forged['merge']['id']=C.identifier(forged['merge'])
    blob=C.git(clone,'hash-object','-w','--stdin',data=C.canonical(forged)).decode().strip()
    C.git(clone,'notes','--ref='+C.RECEIPTS,'add','-f','-C',blob,head)
    try:C.check(clone,'push',base,head,owner,'HlinorAI/test',accept_keys=accept)
    except C.Invalid:pass
    else:raise AssertionError('receipt anchor/order forgery accepted')
    blob=C.git(clone,'hash-object','-w','--stdin',data=C.canonical(bundle)).decode().strip()
    C.git(clone,'notes','--ref='+C.RECEIPTS,'add','-f','-C',blob,head)
    # Signed by the publish Owner, but deliberately broken audit evidence must still fail.
    for mutate in ('head','sequence','receipt'):
        bad=json.loads(json.dumps(record));bad['signature']=None
        if mutate=='head':bad['audit_head']['seq']+=1
        elif mutate=='sequence':bad['audit_chain'][0]['seq']=9
        else:bad['audit_chain'][0]['receipt']='f'*12;bad['audit_chain'][0]['hash']='f'*64
        signed=subprocess.run(['ssh-keygen','-Y','sign','-f',str(f.root/'publish'),'-n','agent-gates-publish'],input=C.payload(bad),capture_output=True)
        assert signed.returncode==0;bad['signature']=signed.stdout.decode()
        blob=C.git(clone,'hash-object','-w','--stdin',data=C.canonical(bad)).decode().strip()
        C.git(clone,'notes','--ref='+C.PUBLISH,'add','-f','-C',blob,head)
        try:C.check(clone,'push',base,head,owner,'HlinorAI/test',accept_keys=accept)
        except C.Invalid:pass
        else:raise AssertionError('invalid signed audit accepted')
    assert f.git('rev-parse','main')==head


for name,fn in [('2 expiration dedupe',dedupe),('7 failed hook cannot change gate result',failed_hook),
                ('7 timeout hook killed without recursion',lambda f:failed_hook(f,True)),('9 dirty agent remains intact',dirty),
                ('10 remove unmerged agent twice preserves branch/evidence',remove),('12 cleanup only unheld registered resources',cleanup),
                ('13 export waits for verification, exact manifest and anchor',export_waits),('16 offline publish export and signed audit verification',attestation)]:case(name,fn)
print('%s passed, %s failed' % (passed,failed));sys.exit(bool(failed))

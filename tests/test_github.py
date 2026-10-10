#!/usr/bin/env python3
"""Phase A offline fixtures. All signing keys are disposable test keys."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

KIT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('checker', KIT / 'bin/github_verify.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
passed = failed = 0


def run(*args, cwd=None, data=None):
    result = subprocess.run([str(a) for a in args], cwd=cwd, input=data, capture_output=True)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors='replace') + result.stdout.decode(errors='replace'))
    return result.stdout.decode().strip()


def g(repo, *args, data=None):
    return run('git', '-C', repo, *args, data=data)


def sign(record, key, namespace):
    record = {k: v for k, v in record.items() if k != 'id'}
    record['signature'] = run('ssh-keygen', '-Y', 'sign', '-f', key, '-n', namespace, data=C.payload(record)) + '\n'
    record['id'] = C.identifier(record)
    return record


def put(repo, ref, commit, record):
    blob = g(repo, 'hash-object', '-w', '--stdin', data=C.canonical(record))
    g(repo, 'notes', '--ref=' + ref, 'add', '-f', '-C', blob, commit)


class Fixture:
    def __init__(self, temp):
        self.temp = Path(temp)
        self.repo = self.temp / 'repo'
        self.repo.mkdir()
        for name in ('owner', 'other', 'gate'):
            run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', self.temp / name)
        self.key = self.temp / 'owner'
        self.anchor = self.key.with_suffix('.pub').read_text()
        g(self.repo, 'init', '-q', '-b', 'main')
        g(self.repo, 'config', 'user.name', 'fixture')
        g(self.repo, 'config', 'user.email', 'fixture@local')
        policy = self.repo / '.agent-gates'
        policy.mkdir()
        for name in ('agent-gates', 'agent_gates.py', 'github_verify.py'):
            shutil.copy2(KIT / 'bin' / name, policy / name)
        (policy / 'allowed_signers').write_text('owner ' + self.anchor)
        (policy / 'config').write_text('MAIN_BRANCH=main\nTEST_CMD="echo fixture passed"\nOWNER_NAME=owner\n'
                                     'OWNER_SIGNING_KEY="' + str(self.key) + '"\n')
        g(self.repo, 'add', '.')
        g(self.repo, 'commit', '-qm', 'initial')
        self.base = g(self.repo, 'rev-parse', 'HEAD')
        wt = self.temp / 'wt'
        g(self.repo, 'worktree', 'add', '-qb', 'agent/codex', wt)
        (wt / 'feature').write_text('feature\n')
        g(wt, 'add', 'feature')
        g(wt, 'commit', '-qm', 'feature')
        cli = policy / 'agent-gates'
        v = run(cli, 'verify', 'agent/codex', '--as', 'claude', cwd=self.repo).splitlines()[-1]
        a = run(cli, 'accept', v, '--yes', cwd=self.repo).splitlines()[-1]
        m = run(cli, 'merge', a, cwd=self.repo).splitlines()[-1]
        self.head = g(self.repo, 'rev-parse', 'HEAD')
        self.bundle = C.note(self.repo, C.RECEIPTS, self.head)
        directory = self.repo / '.git/agent-gates/receipts'
        for kind, identifier in (('verification', v), ('acceptance', a), ('merge', m)):
            assert C.canonical(self.bundle[kind]) == (directory / (kind + '-' + identifier + '.json')).read_bytes()
        self.attest()

    def attest(self, key=None, new=None):
        run(self.repo / '.agent-gates/agent-gates', 'publish', 'attest', self.base, new or self.head,
            '--key', key or self.key, cwd=self.repo)

    def check(self, ok, event='push', head=None, base=None, anchor=None):
        env = {**os.environ, 'AGENT_GATES_OWNER_KEY': self.anchor if anchor is None else anchor}
        out = self.temp / 'report'
        result = subprocess.run([sys.executable, '-I', str(KIT / 'bin/github_verify.py'), '--repo', str(self.repo),
                                 '--event', event, '--before', base or self.base, '--after', head or self.head,
                                 '--repository', 'HlinorAI/hlinor-agent-gates', '--output', str(out)],
                                env=env, capture_output=True)
        report = json.loads((out / 'result.json').read_bytes())
        assert (result.returncode == 0) == ok, result.stdout.decode() + result.stderr.decode()
        assert report['ok'] == ok
        assert (out / 'receipts.json').is_file() and (out / 'summary.md').is_file()
        return report

    def note(self, bundle, commit=None):
        put(self.repo, C.RECEIPTS, commit or self.head, bundle)


def t1(f):
    result = f.check(True)
    assert result['rows'][0]['commit'] == f.head
    assert result['rows'][0]['result'] == 'UNSIGNED VERIFICATION'
    f.check(False, anchor='')


def t2(f):
    g(f.repo, 'notes', '--ref=' + C.PUBLISH, 'remove', f.head)
    f.check(False)


def t3(f):
    f.attest(f.temp / 'other')
    f.check(False)


def t4(f):
    original = C.note(f.repo, C.PUBLISH, f.head)
    for field, value in [('new_main', f.base), ('old_main', f.head), ('commits', [])]:
        changed = sign({**original, field: value}, f.key, 'agent-gates-publish')
        changed.pop('id')  # attestations have no receipt ID
        put(f.repo, C.PUBLISH, f.head, changed)
        f.check(False)


def t5(f):
    (f.repo / '.agent-gates/allowed_signers').write_text('owner ' + (f.temp / 'other.pub').read_text())
    g(f.repo, 'add', '.')
    g(f.repo, 'commit', '-qm', 'replace repository signer')
    head = g(f.repo, 'rev-parse', 'HEAD')
    f.attest(f.temp / 'other', head)
    f.check(False, head=head)


def t6(f):
    g(f.repo, 'notes', '--ref=' + C.RECEIPTS, 'remove', f.head)
    f.check(False)
    changed = copy.deepcopy(f.bundle)
    changed['verification']['result']['summary'] = 'forged'
    f.note(changed)
    f.check(False)
    f.note(f.bundle)
    tree = g(f.repo, 'rev-parse', f.head + '^{tree}')
    second = g(f.repo, 'commit-tree', tree, '-p', f.head, '-p', f.bundle['verification']['head_sha'], '-m', 'agent-gates merge replay')
    replay = copy.deepcopy(f.bundle)
    replay['merge']['merge_commit'] = second
    replay['merge']['id'] = C.identifier(replay['merge'])
    f.note(replay, second)
    f.attest(new=second)
    f.check(False, head=second)


def t7(f):
    v = f.bundle['verification']
    for tree, parents in [(g(f.repo, 'rev-parse', f.base + '^{tree}'), [f.base, v['head_sha']]),
                          (v['merge_tree'], [v['head_sha'], f.base])]:
        args = ['commit-tree', tree]
        for parent in parents:
            args += ['-p', parent]
        head = g(f.repo, *args, '-m', 'agent-gates merge invalid')
        bundle = copy.deepcopy(f.bundle)
        bundle['merge']['merge_commit'] = head
        bundle['merge']['id'] = C.identifier(bundle['merge'])
        f.note(bundle, head)
        f.attest(new=head)
        f.check(False, head=head)


def t8(f):
    f.check(False, event='pull_request', head=f.bundle['verification']['head_sha'])


def t9(f):
    f.check(True, event='pull_request')
    f.check(False, event='pull_request', base=f.bundle['verification']['head_sha'])


def enforced(f):
    bundle = copy.deepcopy(f.bundle)
    v, a, m = (bundle[k] for k in ('verification', 'acceptance', 'merge'))
    v.update(project='fixture', policy_sha=g(f.repo, 'rev-parse', f.base + ':.agent-gates'),
             test_cmd_sha256=C.digest(v['test_cmd'].encode()))
    v = sign(v, f.temp / 'gate', 'agent-gates-receipt')
    a.update(project='fixture', verification_id=v['id'], verification_sha256=C.digest(C.canonical(v)))
    a = sign(a, f.key, 'agent-gates')
    m.update(project='fixture', acceptance_id=a['id'])
    m = sign(m, f.temp / 'gate', 'agent-gates-receipt')
    f.note({'verification': v, 'acceptance': a, 'merge': m})
    assert f.check(True)['rows'][0]['result'] == 'SIGNED VERIFICATION'
    m = sign(m, f.temp / 'other', 'agent-gates-receipt')
    f.note({'verification': v, 'acceptance': a, 'merge': m})
    f.check(False)
    v['signature'] = None
    v['id'] = C.identifier(v)
    a.update(verification_id=v['id'], verification_sha256=C.digest(C.canonical(v)))
    a = sign(a, f.key, 'agent-gates')
    m.update(acceptance_id=a['id'])
    m = sign(m, f.temp / 'gate', 'agent-gates-receipt')
    f.note({'verification': v, 'acceptance': a, 'merge': m})
    f.check(False)


def binding(f):
    for field, value in [('verifier', 'codex'), ('verdict', 'REJECT')]:
        bundle = copy.deepcopy(f.bundle)
        v = bundle['verification']
        v[field] = value
        v['id'] = C.identifier(v)
        a = bundle['acceptance']
        a.update(verification_id=v['id'], verification_sha256=C.digest(C.canonical(v)))
        bundle['acceptance'] = sign(a, f.key, 'agent-gates')
        bundle['merge'].update(acceptance_id=bundle['acceptance']['id'])
        bundle['merge']['id'] = C.identifier(bundle['merge'])
        f.note(bundle)
        f.check(False)
    bundle = copy.deepcopy(f.bundle)
    bundle['acceptance']['expires_at'] = '2000-01-01T00:00:00Z'
    bundle['acceptance'] = sign(bundle['acceptance'], f.key, 'agent-gates')
    bundle['merge']['acceptance_id'] = bundle['acceptance']['id']
    bundle['merge']['id'] = C.identifier(bundle['merge'])
    f.note(bundle)
    f.check(False)


for name, test in [(f'{i} spec fixture', t) for i, t in enumerate((t1,t2,t3,t4,t5,t6,t7,t8,t9), 1)] + \
                  [('enforced signatures and gate key binding', enforced), ('self verification and expired acceptance', binding)]:
    try:
        with tempfile.TemporaryDirectory(prefix='agent-gates-github-test-') as temp:
            f = Fixture(temp)
            before = g(f.repo, 'rev-parse', 'main')
            test(f)
            # Checks/attestations never advance main, except intentional fixture attack #5.
            if test is not t5:
                assert g(f.repo, 'rev-parse', 'main') == before
        passed += 1
        print('PASS ' + name, flush=True)
    except Exception as exc:
        failed += 1
        print('FAIL ' + name + ': ' + str(exc), flush=True)
print(f'{passed} passed, {failed} failed')
sys.exit(bool(failed))

#!/usr/bin/env python3
"""Offline GitHub check. Owner key must come from repository settings, never Git."""
import argparse
import base64
from datetime import datetime
import hashlib
import fnmatch
import shlex
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import tarfile

VERSION = '0.7.0'
RECEIPTS = 'refs/notes/agent-gates'
PUBLISH = 'refs/notes/agent-gates-publish'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identifier(record):
    return digest(canonical({k: v for k, v in record.items() if k != 'id'}))[:12]


def payload(record):
    return canonical({**{k: v for k, v in record.items() if k != 'id'}, 'signature': None})


class Invalid(Exception):
    pass


def require(condition, text):
    if not condition:
        raise Invalid(text)


def git(repo, *args, data=None):
    env = {**os.environ, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    result = subprocess.run(['git', '-c', 'safe.directory=' + str(Path(repo).resolve()),
                             '-c', 'commit.gpgSign=false', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                             '-C', str(repo), *args], input=data, capture_output=True, env=env)
    if result.returncode:
        raise Invalid(result.stderr.decode(errors='replace').strip())
    return result.stdout


def note(repo, ref, commit):
    # `notes show` adds a newline to display; use the stored blob for byte integrity.
    listing = git(repo, 'notes', '--ref=' + ref, 'list', commit).decode().strip()
    require(re.fullmatch(r'[0-9a-f]{40,64}', listing), 'note missing')
    raw = git(repo, 'cat-file', 'blob', listing)
    value = json.loads(raw)
    require(isinstance(value, dict) and canonical(value) == raw, 'note is not canonical JSON')
    return value


def ssh_public(signature):
    """SSHSIG carries the public key; its bytes are bound by Owner acceptance."""
    try:
        lines = signature.strip().splitlines()
        require(lines[0] == '-----BEGIN SSH SIGNATURE-----' and
                lines[-1] == '-----END SSH SIGNATURE-----', 'invalid SSH signature armor')
        binary = base64.b64decode(''.join(lines[1:-1]), validate=True)
        require(binary[:6] == b'SSHSIG' and binary[6:10] == b'\0\0\0\1', 'invalid SSHSIG version')
        length = struct.unpack('>I', binary[10:14])[0]
        key = binary[14:14 + length]
        require(len(key) == length, 'truncated signature key')
        size = struct.unpack('>I', key[:4])[0]
        kind = key[4:4 + size].decode('ascii')
        require(re.fullmatch(r'[a-zA-Z0-9@._+-]+', kind), 'invalid SSH key type')
        return kind + ' ' + base64.b64encode(key).decode()
    except (ValueError, IndexError, TypeError, struct.error, UnicodeError) as exc:
        raise Invalid('invalid SSH signature') from exc


def verify_signature(record, key, identity, namespace):
    require(isinstance(record.get('signature'), str) and record['signature'], 'signature missing')
    require(isinstance(identity, str) and re.fullmatch(r'[a-zA-Z0-9@._+-]+', identity), 'invalid signer identity')
    fields = key.strip().split()
    require(len(fields) >= 2 and '\n' not in key.strip() and '\r' not in key, 'invalid public key')
    with tempfile.TemporaryDirectory(prefix='agent-gates-check-') as temp:
        allowed = Path(temp) / 'allowed'
        signature = Path(temp) / 'signature'
        allowed.write_text(identity + ' ' + ' '.join(fields[:2]) + '\n')
        signature.write_text(record['signature'])
        result = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(allowed), '-I', identity,
                                 '-n', namespace, '-s', str(signature)], input=payload(record), capture_output=True)
    require(result.returncode == 0, 'signature does not match trusted key')


def time_value(value):
    require(isinstance(value, str), 'invalid timestamp')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(result.tzinfo is not None, 'timestamp lacks timezone')
    return result


def receipt(record, kind):
    require(isinstance(record, dict) and record.get('kind') == kind and record.get('schema') == 1,
            'invalid ' + kind + ' receipt')
    require(record.get('id') == identifier(record), 'receipt id/hash mismatch')


def check_merge(repo, commit, accept_keys, used, expected_base=None):
    message = git(repo, 'show', '-s', '--format=%B', commit).decode()
    require(message.startswith('agent-gates merge'), 'commit is not a gate merge')
    bundle = note(repo, RECEIPTS, commit)
    require(set(bundle) == {'verification', 'acceptance', 'merge'}, 'invalid receipt bundle')
    v, a, m = (bundle[k] for k in ('verification', 'acceptance', 'merge'))
    for record, kind in ((v, 'verification'), (a, 'acceptance'), (m, 'merge')):
        receipt(record, kind)
    require(a.get('verification_id') == v['id'] and
            a.get('verification_sha256') == digest(canonical(v)), 'verification binding mismatch')
    require(m.get('acceptance_id') == a['id'] and m.get('merge_commit') == commit, 'merge binding mismatch')
    require(a['id'] not in used, 'acceptance reused in range')
    require(isinstance(v.get('author'), str) and isinstance(v.get('verifier'), str) and
            v['verifier'] != (('agent-' if 'project' in v else '') + v['author']), 'self verification')
    require(v.get('verdict') == 'ACCEPT' and v.get('result', {}).get('exit') == 0 and
            not v.get('result', {}).get('timed_out') and not v.get('baseline', {}).get('timed_out'),
            'verification rejected')
    require(time_value(a['created_at']) <= time_value(m['created_at']) <= time_value(a['expires_at']),
            'merge outside acceptance lifetime')
    require(time_value(v['created_at']) <= time_value(a['created_at']), 'acceptance predates verification')
    keys = [line.strip() for line in accept_keys.splitlines() if line.strip()]
    require(keys, 'AGENT_GATES_ACCEPT_KEYS missing for gate merge')
    accepted = False
    for key in keys:
        try:
            verify_signature(a, key, a.get('owner'), 'agent-gates')
            accepted = True
            break
        except Invalid:
            continue
    require(accepted, 'acceptance signature does not match AGENT_GATES_ACCEPT_KEYS')
    tree = git(repo, 'show', '-s', '--format=%T', commit).decode().strip()
    parents = git(repo, 'show', '-s', '--format=%P', commit).decode().split()
    require(tree == v.get('merge_tree'), 'merge tree mismatch')
    require(parents == [v.get('base_sha'), v.get('head_sha')], 'merge parents mismatch')
    if expected_base is not None:
        require(v['base_sha'] == expected_base, 'PR base mismatch')
    require(v.get('branch') == 'agent/' + v['author'] and v.get('test_cmd'), 'invalid verification branch')
    config = {}
    for line in git(repo, 'show', v['base_sha'] + ':.agent-gates/config').decode().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        require(separator and re.fullmatch(r'[A-Z_]+', key), 'invalid committed policy')
        parts = shlex.split(value, comments=True)
        require(len(parts) == 1, 'invalid committed policy value')
        config[key] = parts[0]
    require(config.get('TEST_CMD') == v['test_cmd'], 'test command differs from base policy')
    if 'project' not in v:
        require(config.get('OWNER_NAME') == a.get('owner'), 'acceptance Owner differs from base policy')
    changed = git(repo, 'diff', '--no-ext-diff', '--no-textconv', '--name-only', '--no-renames', '-z',
                  v['base_sha'] + '...' + v['head_sha']).decode().split('\0')
    fixed = {'GIT_POLICY.md', 'GIT_POLICY.agent-gates.md', 'VERIFIER.md', 'VERIFIER.agent-gates.md'}
    patterns = config.get('POLICY_PATHS', '').split()
    policy_changed = any(path and (path.startswith('.agent-gates/') or path in fixed or
                         any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)) for path in changed)
    policy_mode = config.get('POLICY_CHANGES', 'deny')
    require(policy_mode in ('deny', 'warn'), 'invalid policy mode')
    require(policy_mode != 'deny' or not policy_changed or a.get('allow_policy_change') is True,
            'policy change lacks signed Owner override')
    mode = 'UNSIGNED VERIFICATION'
    if 'project' in v:
        require(v.get('project') == a.get('project') == m.get('project'), 'project binding mismatch')
        gate_key = ssh_public(v.get('signature'))
        verify_signature(v, gate_key, 'agent-gates', 'agent-gates-receipt')
        verify_signature(m, gate_key, 'agent-gates', 'agent-gates-receipt')
        require(v.get('test_cmd_sha256') == digest(v['test_cmd'].encode()), 'test command hash mismatch')
        policy = git(repo, 'rev-parse', v['base_sha'] + ':.agent-gates').decode().strip()
        require(v.get('policy_sha') == policy, 'policy hash mismatch')
        mode = 'SIGNED VERIFICATION'
    used.add(a['id'])
    return {'commit': commit, 'kind': 'gate merge', 'author': v['author'], 'verifier': v['verifier'],
            'tests': v['result'].get('summary', ''), 'acceptance_id': a['id'], 'result': mode}, bundle


def audit_chain(raw):
    rows=[];head='0'*64
    for line in raw.splitlines(keepends=True):
        try:row=json.loads(line)
        except ValueError:raise Invalid('unreadable audit chain')
        require(isinstance(row,dict) and canonical(row)+b'\n'==line,'noncanonical audit event')
        require(type(row.get('seq')) is int and row['seq']==len(rows)+1 and row.get('prev')==head,
                'audit sequence/predecessor mismatch')
        require(row.get('hash')==digest(canonical({k:v for k,v in row.items() if k!='hash'})),
                'audit hash mismatch')
        head=row['hash'];rows.append(row)
    return rows,dict(seq=len(rows),hash=head)


def audit_snapshot(repo, export):
    if export:
        with tarfile.open(export,'r:gz') as archive:
            members=archive.getmembers()
            require(all(m.isfile() and '/' not in m.name and m.name not in ('.','..') for m in members),
                    'unsafe audit export member')
            require(len({m.name for m in members})==len(members),'duplicate audit export member')
            files={m.name:archive.extractfile(m).read() for m in members}
        require('MANIFEST.json' in files,'audit export manifest missing')
        manifest=json.loads(files.pop('MANIFEST.json'))
        require(manifest.get('files')=={name:digest(data) for name,data in files.items()},'audit export hash mismatch')
        rows,head=audit_chain(files.get('audit.jsonl',b''))
        require(manifest.get('seq')==head['seq'] and manifest.get('head')==head['hash'],'audit export head mismatch')
        return rows,head
    common=Path(git(repo,'rev-parse','--path-format=absolute','--git-common-dir').decode().strip())
    path=common/'agent-gates/receipts/audit.jsonl'
    require(path.is_file(),'server audit missing: use --audit-export from export-audit')
    return audit_chain(path.read_bytes())


def publish_mode(repo, commit):
    config = {}
    for line in git(repo, 'show', commit + ':.agent-gates/config').decode().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        parts = shlex.split(value, comments=True)
        require(sep and re.fullmatch(r'[A-Z_]+', key) and len(parts) == 1,
                'invalid committed publish policy')
        config[key] = parts[0]
    mode = config.get('AUDIT_PUBLISH', 'head')
    require(mode in ('head', 'chain'), 'invalid AUDIT_PUBLISH')
    return mode


def checked_head(record):
    head = record.get('audit_head')
    require(isinstance(head, dict) and set(head) == {'seq', 'hash'} and
            type(head['seq']) is int and head['seq'] >= 0 and
            isinstance(head['hash'], str) and re.fullmatch(r'[a-f0-9]{64}', head['hash']),
            'invalid publish audit head')
    require(head['seq'] != 0 or head['hash'] == '0' * 64, 'invalid empty audit head')
    return head


def previous_head(repo, before, owner_key, name):
    # Only notes attached to earlier first-parent main commits are checkpoints.
    notes = dict(line.split()[::-1] for line in
                 git(repo, 'notes', '--ref=' + PUBLISH, 'list').decode().splitlines())
    for commit in git(repo, 'rev-list', '--first-parent', before).decode().split():
        if commit not in notes:
            continue
        raw = git(repo, 'cat-file', 'blob', notes[commit])
        try:
            record = json.loads(raw)
        except (ValueError, UnicodeError):
            continue  # Unreadable historical notes are not checkpoint records.
        if not isinstance(record, dict) or 'audit_head' not in record:
            continue  # Owner-only pushes and unrelated notes need no current-key signature.
        try:
            require(canonical(record) == raw, 'checkpoint is not canonical JSON')
            require(record.get('kind') == 'publish' and record.get('schema') == 1 and
                    record.get('repo') == name and record.get('new_main') == commit,
                    'previous publish checkpoint binding mismatch')
            verify_signature(record, owner_key, 'owner', 'agent-gates-publish')
            return checked_head(record)
        except (Invalid, OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
            raise Invalid('PREVIOUS_HEAD_UNVERIFIED: ' + str(exc)) from exc
    return None


def check_head_attestation(record, bundles, commits):
    head = checked_head(record)
    require('audit_chain' not in record, 'head attestation discloses audit rows')
    previous = 0
    used = set()
    for commit in commits:
        if commit not in bundles:
            continue
        for kind in ('verification', 'acceptance', 'merge'):
            receipt = bundles[commit][kind]
            require(receipt['id'] not in used, 'receipt reused across bundles')
            used.add(receipt['id'])
            seq = receipt.get('audit_seq')
            require(type(seq) is int and 0 < seq <= head['seq'], 'receipt audit sequence out of range')
            require(isinstance(receipt.get('audit_prev'), str) and
                    re.fullmatch(r'[a-f0-9]{64}', receipt['audit_prev']), 'invalid receipt audit predecessor')
            require(seq > previous, 'receipt audit ordering mismatch')
            previous = seq


def check_audit_attestation(record, bundles, commits):
    audited=[bundles[c] for c in commits if c in bundles and 'verification' in bundles[c]
             and any('audit_seq' in bundles[c][kind] for kind in ('verification','acceptance','merge'))]
    mode = record.get('audit_publish', 'chain')  # v0.6 attestations embed the chain.
    require(mode in ('head', 'chain'), 'invalid attestation audit mode')
    if mode == 'head':
        check_head_attestation(record, bundles, commits)
        return
    if not audited:return  # Immutable v0.5 receipts predate audit anchors.
    require('audit_chain' in record and 'audit_head' in record,'publish audit anchor missing')
    rows,head=audit_chain(b''.join(canonical(row)+b'\n' for row in record['audit_chain']))
    require(record['audit_head']==head,'publish audit head mismatch')
    invalidated={i for row in rows if row.get('event')=='reseal' for i in row.get('invalidated_receipts',[])}
    last_merge=0
    for bundle in audited:
        seqs=[]
        for kind,event in (('verification','verify'),('acceptance','accept'),('merge','merge')):
            receipt=bundle[kind];seq=receipt.get('audit_seq')
            if 'audit_seq' not in receipt and 'audit_prev' not in receipt and not seqs:
                continue  # Immutable pre-v0.6 evidence may precede new anchored receipts.
            require(type(seq) is int and 0<seq<=len(rows),'receipt audit sequence out of range')
            row=rows[seq-1]
            require(receipt['id'] not in invalidated,'receipt invalidated by reseal')
            require(row['prev']==receipt.get('audit_prev') and
                    (row.get('event')==event or (row.get('event')=='recovered' and
                     row.get('original_event')==event and row.get('original_audit_seq')==seq and
                     row.get('original_audit_prev')==receipt.get('audit_prev'))),'receipt audit binding mismatch')
            seqs.append(seq)
        require(seqs and all(left<right for left,right in zip(seqs,seqs[1:])) and
                seqs[-1]>last_merge,'receipt audit ordering mismatch')
        last_merge=seqs[-1]


def attest(repo, old, new, key, name, audit_export=None):
    old = git(repo, 'rev-parse', '--verify', old + '^{commit}').decode().strip()
    new = git(repo, 'rev-parse', '--verify', new + '^{commit}').decode().strip()
    git(repo, 'merge-base', '--is-ancestor', old, new)
    commits = git(repo, 'rev-list', '--first-parent', '--reverse', old + '..' + new).decode().split()
    record = {'kind': 'publish', 'schema': 1, 'repo': name, 'old_main': old, 'new_main': new,
              'commits': commits, 'created_at': datetime.now().astimezone().isoformat(),
              'tool_version': VERSION, 'signature': None}
    gate_commits=[c for c in commits if git(repo,'show','-s','--format=%B',c).decode().startswith('agent-gates merge')]
    if gate_commits:
        audited=any('audit_seq' in note(repo,RECEIPTS,c)['merge'] for c in gate_commits)
        if audited or audit_export:
            chain, record['audit_head'] = audit_snapshot(repo, audit_export)
            record['audit_publish'] = publish_mode(repo, new)
            if record['audit_publish'] == 'chain':
                record['audit_chain'] = chain
    return sign_publish_note(repo, new, record, key)


def sign_publish_note(repo, commit, record, key):
    result = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(key), '-n', 'agent-gates-publish'],
                            input=payload(record), capture_output=True)
    require(result.returncode == 0, 'could not sign publish attestation')
    record = {**record, 'signature': result.stdout.decode()}
    # Store exact canonical bytes, without Git's text cleanup or trailing LF.
    blob = git(repo, 'hash-object', '-w', '--stdin', data=canonical(record)).decode().strip()
    git(repo, 'notes', '--ref=' + PUBLISH, 'add', '-f', '-C', blob, commit)
    return record


def resign_checkpoint(repo, commit, old_key, key):
    commit = git(repo, 'rev-parse', '--verify', commit + '^{commit}').decode().strip()
    record = note(repo, PUBLISH, commit)
    require(record.get('kind') == 'publish' and record.get('schema') == 1 and
            record.get('new_main') == commit, 'invalid publish checkpoint binding')
    checked_head(record)
    verify_signature(record, Path(old_key).read_text(), 'owner', 'agent-gates-publish')
    # Preserve every field except signature, including time, range and audit_head.
    return sign_publish_note(repo, commit, record, key)


def check(repo, event, before, after, owner_key, name, rows=None, bundles=None, accept_keys=None):
    accept_keys = os.environ.get('AGENT_GATES_ACCEPT_KEYS', '') if accept_keys is None else accept_keys
    used = set()
    rows = [] if rows is None else rows
    bundles = {} if bundles is None else bundles
    if event == 'push':
        require(bool(owner_key.strip()), 'AGENT_GATES_OWNER_KEY missing')
        require(re.fullmatch(r'[0-9a-f]{40,64}', before or '') and
                re.fullmatch(r'[0-9a-f]{40,64}', after or ''), 'invalid event range')
        require(set(before) != {'0'}, 'initial push has no attested base')
        git(repo, 'merge-base', '--is-ancestor', before, after)
        commits = git(repo, 'rev-list', '--first-parent', '--reverse', before + '..' + after).decode().split()
        attestation = note(repo, PUBLISH, after)
        bundles['publish'] = attestation
        require(attestation.get('kind') == 'publish' and attestation.get('schema') == 1 and
                attestation.get('repo') == name and attestation.get('new_main') == after and
                attestation.get('old_main') == before and attestation.get('commits') == commits,
                'publish attestation range mismatch')
        time_value(attestation['created_at'])
        verify_signature(attestation, owner_key, 'owner', 'agent-gates-publish')
        for commit in commits:
            message = git(repo, 'show', '-s', '--format=%B', commit).decode()
            if message.startswith('agent-gates merge'):
                bundles[commit] = note(repo, RECEIPTS, commit)
                row, bundle = check_merge(repo, commit, accept_keys, used)
                rows.append(row)
                bundles[commit] = bundle
            else:
                rows.append({'commit': commit, 'kind': 'Owner attested',
                             'author': git(repo, 'show', '-s', '--format=%an', commit).decode().strip(),
                             'verifier': '', 'tests': '', 'acceptance_id': '', 'result': 'PASS'})
        if 'audit_publish' in attestation:
            require(attestation['audit_publish'] == publish_mode(repo, after), 'publish mode differs from main policy')
        check_audit_attestation(attestation,bundles,commits)
        if 'audit_head' in attestation:
            current = checked_head(attestation)
            checkpoint = previous_head(repo, before, owner_key, name)
            require(checkpoint is None or current['seq'] >= checkpoint['seq'],
                    'publish audit head decreased since previous checkpoint')
            require(checkpoint is None or current['seq'] != checkpoint['seq'] or
                    current['hash'] == checkpoint['hash'],
                    'publish audit hash differs at equal sequence')
    else:
        bundles[after] = note(repo, RECEIPTS, after)
        row, bundle = check_merge(repo, after, accept_keys, used, before)
        rows.append(row)
        bundles[after] = bundle
    return rows, bundles


def summary(rows, error=None):
    columns = ('commit', 'kind', 'author', 'verifier', 'tests', 'acceptance_id', 'result')
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')
    lines = ['| ' + ' | '.join(columns) + ' |', '| ' + ' | '.join(['---'] * len(columns)) + ' |']
    lines += ['| ' + ' | '.join(cell(row.get(c, '')) for c in columns) + ' |' for row in rows]
    if error:
        lines += ['Check failed: ' + cell(error)]
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', default='.')
    parser.add_argument('--event', choices=['push', 'pull_request'], required=True)
    parser.add_argument('--before', required=True)
    parser.add_argument('--after', required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--output', default='agent-gates-report')
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    rows, bundles, error = [], {}, None
    try:
        rows, bundles = check(args.repo, args.event, args.before, args.after,
                              os.environ.get('AGENT_GATES_OWNER_KEY', ''), args.repository, rows, bundles)
    except (Invalid, OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        error = str(exc)
        rows.append({'commit': args.after, 'kind': args.event, 'result': 'FAIL'})
    report = summary(rows, error)
    if args.event == 'pull_request':
        report = ('PR result is advisory: v0.5 does not enforce workflow integrity.\n\n' + report)
    (output / 'summary.md').write_text(report)
    (output / 'receipts.json').write_bytes(canonical(bundles))
    (output / 'result.json').write_bytes(canonical({'ok': error is None, 'error': error, 'rows': rows}))
    print(report, end='')
    return 1 if error else 0


if __name__ == '__main__':
    sys.exit(main())

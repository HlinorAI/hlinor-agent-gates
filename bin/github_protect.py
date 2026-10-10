#!/usr/bin/env python3
"""Owner-operated GitHub protection; subprocess gh is the only network gateway."""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys


class Deny(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message


def repository(value):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value):
        raise Deny('INVALID_REPOSITORY', 'expected owner/repository')
    return value


def public_key(text):
    fields = text.strip().split()
    try:
        if len(fields) < 2 or '\n' in text.strip() or '\r' in text:
            raise ValueError()
        raw = base64.b64decode(fields[1], validate=True)
        size = struct.unpack('>I', raw[:4])[0]
        if raw[4:4 + size].decode() != fields[0]:
            raise ValueError()
    except (ValueError, UnicodeError, struct.error):
        raise Deny('INVALID_PUBLIC_KEY', 'expected a single SSH public key')
    return ' '.join(fields[:2])


def api(repo, method, suffix, body=None, missing=False, pages=False):
    args = ['gh', 'api', '--method', method, 'repos/' + repo + suffix,
            '-H', 'Accept: application/vnd.github+json']
    if pages:
        args += ['--paginate', '--slurp']
    data = None
    if body is not None:
        args += ['--input', '-']
        data = json.dumps(body).encode()
    result = subprocess.run(args, input=data, capture_output=True)
    if result.returncode:
        if missing and re.search(rb'HTTP 404\b', result.stderr):
            return None
        raise Deny('GITHUB_API_FAILED', result.stderr.decode(errors='replace').strip())
    return json.loads(result.stdout) if result.stdout.strip() else None


def set_variable(repo, name, value, previous):
    if previous is not None and previous.get('value') == value:
        return
    body = {'name': name, 'value': value}
    if previous is None:
        api(repo, 'POST', '/actions/variables', body)
    else:
        api(repo, 'PATCH', '/actions/variables/' + name, body)


def actors(value):
    return {'users': [v['login'] for v in value.get('users', [])],
            'teams': [v['slug'] for v in value.get('teams', [])],
            'apps': [v['slug'] for v in value.get('apps', [])]}


def protect(args):
    repo = repository(args.repository)
    key = public_key(Path(args.owner_key).read_text())
    pinned = api(repo, 'GET', '/actions/variables/AGENT_GATES_OWNER_KEY', missing=True)
    old = public_key(pinned['value']) if pinned else None
    if old and old != key:
        if not args.rotate or not args.rotation_signature:
            raise Deny('OWNER_KEY_CHANGED', 'rotation requires --rotate and the old key signature')
        spec = importlib.util.spec_from_file_location('check', Path(__file__).with_name('github_verify.py'))
        check = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(check)
        record = {'kind': 'owner-key-rotation', 'schema': 1, 'repo': repo,
                  'old_key': old, 'new_key': key, 'signature': Path(args.rotation_signature).read_text()}
        try:
            check.verify_signature(record, old, 'owner', 'agent-gates-publish')
        except check.Invalid:
            raise Deny('OWNER_KEY_CHANGED', 'old key rotation signature is invalid')
    acceptance = None
    if args.accept_keys:
        keys = [public_key(line) for line in Path(args.accept_keys).read_text().splitlines() if line.strip()]
        if not keys:
            raise Deny('INVALID_PUBLIC_KEY', 'acceptance key list is empty')
        acceptance = '\n'.join(dict.fromkeys(keys))
    info = api(repo, 'GET', '')
    if not info.get('permissions', {}).get('admin'):
        raise Deny('ADMIN_REQUIRED', 'github protect requires repository admin permission')
    current = api(repo, 'GET', '/branches/main/protection', missing=True) or {}
    checks = current.get('required_status_checks') or {}
    contexts = set(checks.get('contexts', [])) | {c['context'] for c in checks.get('checks', [])}
    runs = api(repo, 'GET', '/commits/main/check-runs?per_page=100', pages=True)
    for page in runs:
        contexts.update(run['name'] for run in page.get('check_runs', [])
                        if run['name'] != 'agent-gates/notify')
    # An empty CI history must not silently install protection with only our check.
    if not contexts - {'agent-gates/verify'}:
        raise Deny('CI_CHECKS_MISSING', 'run existing CI on main before configuring protection')
    contexts.add('agent-gates/verify')
    app_ids = {c['context']: c.get('app_id', -1) for c in checks.get('checks', [])}
    required = {'strict': True, 'checks': [{'context': c, 'app_id': app_ids.get(c, -1)} for c in sorted(contexts)]}
    reviews = current.get('required_pull_request_reviews')
    if reviews:
        reviews = {k: v for k, v in reviews.items() if k in {
            'dismiss_stale_reviews', 'require_code_owner_reviews', 'required_approving_review_count',
            'require_last_push_approval', 'dismissal_restrictions', 'bypass_pull_request_allowances'}}
        for field in ('dismissal_restrictions', 'bypass_pull_request_allowances'):
            if field in reviews:
                reviews[field] = actors(reviews[field])
    restrictions = current.get('restrictions')
    body = {'required_status_checks': required, 'enforce_admins': bool(current.get('enforce_admins', {}).get('enabled')),
            'required_pull_request_reviews': reviews, 'restrictions': actors(restrictions) if restrictions else None,
            'allow_force_pushes': False, 'allow_deletions': False}
    for field in ('required_linear_history', 'required_conversation_resolution', 'block_creations',
                  'lock_branch', 'allow_fork_syncing'):
        if field in current:
            body[field] = current[field]['enabled']
    # Complete all validation before the first remote mutation.
    previous_accept = api(repo, 'GET', '/actions/variables/AGENT_GATES_ACCEPT_KEYS', missing=True) if acceptance else None
    set_variable(repo, 'AGENT_GATES_OWNER_KEY', key, pinned)
    if acceptance:
        set_variable(repo, 'AGENT_GATES_ACCEPT_KEYS', acceptance, previous_accept)
    api(repo, 'PUT', '/branches/main/protection', body)
    result = api(repo, 'GET', '/branches/main/protection')
    print(json.dumps(result, sort_keys=True, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--repository', default='HlinorAI/hlinor-agent-gates')
    parser.add_argument('--owner-key', required=True)
    parser.add_argument('--accept-keys')
    parser.add_argument('--rotate', action='store_true')
    parser.add_argument('--rotation-signature')
    args = parser.parse_args(argv)
    try:
        protect(args)
        return 0
    except Deny as exc:
        print('DENY ' + exc.code + ': ' + ' '.join(exc.message.splitlines()))
        return 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('ERROR: ' + ' '.join(str(exc).splitlines()), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

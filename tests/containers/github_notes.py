#!/usr/bin/env python3
"""Run only after phase_b.sh inside its disposable container."""
import importlib.util
from pathlib import Path
import json
import os

assert Path('/.dockerenv').exists() or Path('/run/.containerenv').exists()
assert os.geteuid() == 0
spec = importlib.util.spec_from_file_location('check', '/kit/bin/github_verify.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
repo = '/srv/agent-gates/project.git'
owner_key = Path('/opt/agent-gates/owner_allowed_signers').read_text().split(' ', 1)[1].strip()
receipts = Path('/var/lib/agent-gates/projects/project/receipts')
count = 0
for path in receipts.glob('merge-*.json'):
    m = json.loads(path.read_bytes())
    a = json.loads((receipts / ('acceptance-' + m['acceptance_id'] + '.json')).read_bytes())
    v = json.loads((receipts / ('verification-' + a['verification_id'] + '.json')).read_bytes())
    bundle = C.note(repo, C.RECEIPTS, m['merge_commit'])
    assert bundle == {'verification': v, 'acceptance': a, 'merge': m}
    row, _ = C.check_merge(repo, m['merge_commit'], owner_key, set())
    assert row['result'] == 'SIGNED VERIFICATION'
    count += 1
assert count > 0
print('1 passed, 0 failed (real enforced receipt notes, ' + str(count) + ' merges)')

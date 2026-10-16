#!/usr/bin/env python3
"""v0.7.1 regressions; provisioning is allowed only in the disposable suite container."""
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess

assert (Path('/.dockerenv').exists() or Path('/run/.containerenv').exists()) and os.geteuid() == 0
CLI = '/opt/agent-gates/bin/agent-gates'
PROJECT = 'pytest-regression'
BARE = '/srv/agent-gates/' + PROJECT + '.git'
SOURCE = Path('/root') / PROJECT
CLONE = '/home/agent-codex/work/' + PROJECT
RECEIPTS = Path('/var/lib/agent-gates/projects') / PROJECT / 'receipts'


def run(*args, ok=True, cwd=None):
    result = subprocess.run(list(map(str, args)), cwd=cwd, text=True, capture_output=True)
    if ok:
        assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result


def git(*args):
    return run('runuser', '-u', 'agent-gates', '--', 'git', '--git-dir=' + BARE, *args).stdout.strip()


def review(ok=True):
    # SSH starts here, not in the usually searchable clone directory.
    home = Path('/home/agent-claude')
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    return run('runuser', '-u', 'agent-claude', '--', 'sudo', '-n', '-u', 'agent-gates',
               CLI, 'verify', PROJECT, 'agent/codex', cwd=home, ok=ok)


SOURCE.mkdir()
(SOURCE / '.agent-gates').mkdir()
(SOURCE / 'tests').mkdir()
(SOURCE / '.agent-gates/config').write_text('MAIN_BRANCH=main\nTEST_CMD="python3 -m pytest tests -q"\nOWNER_NAME=root\nOWNER_SIGNING_KEY=""\n')
(SOURCE / 'cache_helper.py').write_text('VALUE = 42\n')
(SOURCE / 'tests/test_cache.py').write_text('''from pathlib import Path
import importlib.util

def test_real_pytest_caches(tmp_path, pytestconfig):
    (tmp_path / 'temporary').write_text('runner-owned')
    source = Path.cwd() / 'cache_helper.py'
    spec = importlib.util.spec_from_file_location('cache_helper', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.VALUE == 42
    assert list(Path('__pycache__').glob('*.pyc'))
    pytestconfig.cache.set('regression/proof', 42)
    assert Path('.pytest_cache').is_dir()
''')
run('git', 'init', '-q', '-b', 'main', SOURCE)
run('git', '-C', SOURCE, 'config', 'user.name', 'test')
run('git', '-C', SOURCE, 'config', 'user.email', 'test@invalid')
run('git', '-C', SOURCE, 'add', '.')
run('git', '-C', SOURCE, 'commit', '-qm', 'real pytest fixture')
# No system-wide safe.directory workaround: exact per-agent trust must suffice.
assert run('git', 'config', '--system', '--get-all', 'safe.directory', ok=False).returncode == 1
run('/trusted-kit/bin/agent-gates', 'enforce', 'init', SOURCE, '--agents', 'codex,claude,zcode')
assert 'VERSION_ID="24.04"' in Path('/etc/os-release').read_text()
version = run('git', '--version').stdout.strip()
for account in ('agent-codex', 'agent-claude', 'agent-zcode'):
    paths = run('runuser', '-u', account, '--', 'git', 'config', '--global', '--get-all', 'safe.directory').stdout.splitlines()
    assert BARE in paths and '/srv/agent-gates/project.git' in paths, paths
    assert not any('*' in path for path in paths), paths
    run('runuser', '-u', account, '--', 'git', '-C', '/home/' + account + '/work/' + PROJECT, 'fetch', 'gate', 'main')
print('PASS exact per-project trust, multiple projects and clones without system workaround (' + version + ')', flush=True)

for args in (('commit', '--allow-empty', '-qm', 'author feature'), ('push', 'gate', 'agent/codex')):
    run('runuser', '-u', 'agent-codex', '--', 'git', '-C', CLONE, *args)
base = git('rev-parse', 'main')
# An actual undeletable runner file must fail closed with a bounded, escaped path.
blocked = Path('/tmp/agent-gates-cleanup-refusal')
blocked.mkdir(mode=0o755)
name = blocked / 'blocked\n\x1b[31m.txt'
name.write_text('PRIVATE CONTENT MUST NEVER APPEAR')
runner = pwd.getpwnam('ag-runner')
os.chown(name, runner.pw_uid, runner.pw_gid)
try:
    result = review(ok=False)
    message = result.stdout + result.stderr
    assert result.returncode == 1 and message.startswith('DENY RUNNER_CLEANUP_FAILED:'), message
    assert json.dumps(str(name), ensure_ascii=True) in message, message
    assert len(message.splitlines()) == 1 and '\x1b' not in message, message
    assert 'PRIVATE CONTENT' not in message
    assert name.read_text() == 'PRIVATE CONTENT MUST NEVER APPEAR'
    assert git('rev-parse', 'main') == base
finally:
    shutil.rmtree(blocked)
print('PASS cleanup DENY names first undeleted path, escapes controls, leaks no contents, preserves main', flush=True)


# Private foreign directories cannot contain files the runner could create.
# Keep them during the negative scan too: diagnostics must skip these paths.
private_dirs = [Path(root) / 'systemd-private-x' for root in ('/tmp', '/var/tmp')]
for private in private_dirs:
    private.mkdir(mode=0o700)
    (private / 'private-content').write_text('NEIGHBOR SECRET CONTENT')

# Writable but unreadable foreign directories can hide runner files: fail closed.
opaque = Path('/tmp/agent-gates-writable-neighbor')
opaque.mkdir()
opaque.chmod(0o733)
(opaque / 'runner-file').write_text('RUNNER SECRET CONTENT')
os.chown(opaque / 'runner-file', runner.pw_uid, runner.pw_gid)
try:
    result = review(ok=False)
    message = result.stdout + result.stderr
    assert result.returncode == 1 and message.startswith('DENY RUNNER_CLEANUP_FAILED:'), message
    assert json.dumps(str(opaque)) in message, message
    assert all(str(private) not in message for private in private_dirs), message
    assert 'SECRET CONTENT' not in message and len(message.splitlines()) == 1
    assert (opaque / 'runner-file').read_text() == 'RUNNER SECRET CONTENT'
    assert git('rev-parse', 'main') == base
finally:
    shutil.rmtree(opaque)
print('PASS foreign 0733 directory with runner file denies, skips private paths in diagnostics and preserves main', flush=True)

try:
    result = review()
    ident = result.stdout.strip().splitlines()[-1]
    record = json.loads((RECEIPTS / ('verification-' + ident + '.json')).read_text())
    assert record['verdict'] == 'ACCEPT' and record['test_cmd'] == 'python3 -m pytest tests -q'
    assert record['result']['exit'] == 0 and record['baseline']['exit'] == 0
    assert '1 passed' in record['result']['summary'] and '1 passed' in record['baseline']['summary']
    assert record['verifier'] == 'agent-claude' and git('rev-parse', 'main') == base
    for root in ('/tmp', '/var/tmp', '/dev/shm'):
        remaining = run('find', root, '-xdev', '-user', 'ag-runner', '-print').stdout
        assert not remaining, remaining
    print('PASS private SSH home with pytest tmp_path, __pycache__, .pytest_cache; branch+baseline pass and no runner temp files remain', flush=True)
    for private in private_dirs:
        assert stat.S_IMODE(private.stat().st_mode) == 0o700
        assert (private / 'private-content').read_text() == 'NEIGHBOR SECRET CONTENT'
    assert git('rev-parse', 'main') == base
    print('PASS root 0700 systemd-private-x in /tmp and /var/tmp is pruned; verify succeeds and foreign files/main remain unchanged', flush=True)
finally:
    for private in private_dirs:
        shutil.rmtree(private)
a = run(CLI, 'accept', ident, '--yes').stdout.strip().splitlines()[-1]
run('runuser', '-u', 'agent-codex', '--', 'sudo', '-n', '-u', 'agent-gates', CLI, 'merge', PROJECT, a)
assert git('rev-parse', 'main') != base
run(CLI, 'doctor', PROJECT)
print('PASS signed Owner acceptance, gated merge and doctor after pytest cleanup', flush=True)
print('6 passed, 0 failed (v0.7.1 container regressions)', flush=True)

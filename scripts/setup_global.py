"""Machine setup, stdlib only. All state is scoped to HOME/GIT_CONFIG_GLOBAL."""
import argparse
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
from instructions import GLOBAL, update


def git(*args):
    return subprocess.run(['git', 'config', '--global', *args], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def write(path, text):
    if not path.exists() or path.read_text() != text:
        path.write_text(text)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--agents')
    parser.add_argument('--root', action='append')
    parser.add_argument('--uninstall', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    home = Path.home()
    target = home / '.agent-gates'
    template = target / 'git-template'
    current = git('--get-all', 'init.templateDir')
    if current.returncode not in (0, 1):
        raise ValueError(current.stderr.strip())
    if any(Path(os.path.expanduser(value)).resolve() != template.resolve()
           for value in current.stdout.splitlines()):
        raise ValueError('init.templateDir already points elsewhere; unset it with '
                         "git config --global --unset-all init.templateDir before setup")
    agents = args.agents or 'codex,claude,zcode'
    if any(not re.fullmatch('[a-z0-9-]+', name) for name in agents.split(',')):
        raise ValueError('invalid agent name')
    roots = [str(Path(root).expanduser().resolve()) for root in (args.root or [])]
    if any('\n' in root for root in roots):
        raise ValueError('root paths cannot contain newlines')
    rules = [home / '.claude/CLAUDE.md',
             Path(os.environ.get('CODEX_HOME', str(home / '.codex'))) / 'AGENTS.md',
             home / '.gemini/GEMINI.md']
    if args.dry_run:
        print(('Uninstall' if args.uninstall else 'Install') + ' agent-gates: ' + str(target))
        print('init.templateDir: ' + str(template))
        return
    if args.uninstall:
        if current.returncode == 0:
            result = git('--unset-all', 'init.templateDir')
            if result.returncode:
                raise ValueError(result.stderr.strip())
        for path in rules:
            if path.is_file():
                update(path, None)
        print('agent-gates: global configuration removed; kit and projects retained')
        return
    source = Path(__file__).resolve().parent.parent
    kit = target / 'kit'
    kit.mkdir(parents=True, exist_ok=True)
    # Copy distributable kit content only; never copy Git state or personal artifacts.
    for name in ('bin', 'templates', 'scripts', 'docs', 'tests', '.github',
                 'init.sh', 'setup-global.sh', 'README.md', 'CHANGELOG.md', 'LICENSE'):
        src = source / name
        if not src.exists():
            continue
        files = src.rglob('*') if src.is_dir() else [src]
        for item in files:
            if not item.is_file() or '__pycache__' in item.parts:
                continue
            dst = kit / item.relative_to(source)
            if item.resolve() == dst.resolve():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            if not dst.exists() or dst.read_bytes() != item.read_bytes():
                shutil.copy2(item, dst)
    defaults = target / 'defaults'
    if not defaults.exists():
        owner = os.environ.get('OWNER_NAME') or git('--get', 'user.name').stdout.strip() or 'owner'
        write(defaults, ''.join(key + '=' + shlex.quote(value) + '\n' for key, value in
                               [('AGENTS', agents), ('OWNER_NAME', owner),
                                ('TEST_CMD', os.environ.get('TEST_CMD', ''))]))
    elif args.agents:
        lines = defaults.read_text().splitlines()
        assignment = 'AGENTS=' + shlex.quote(agents)
        if any(line.startswith('AGENTS=') for line in lines):
            lines = [assignment if line.startswith('AGENTS=') else line for line in lines]
        else:
            lines.append(assignment)
        write(defaults, '\n'.join(lines) + '\n')
    if args.root is not None or not (target / 'roots').exists():
        write(target / 'roots', ''.join(root + '\n' for root in dict.fromkeys(roots)))
    hooks = template / 'hooks'
    hooks.mkdir(parents=True, exist_ok=True)
    hook = hooks / 'post-commit'
    write(hook, (source / 'templates/post-commit').read_text())
    hook.chmod(0o755)
    for path in rules:
        if path.parent.is_dir():
            update(path, GLOBAL)
    result = git('--replace-all', 'init.templateDir', str(template))
    if result.returncode:
        raise ValueError(result.stderr.strip())
    print('agent-gates: setup complete; roots: ' + ', '.join(roots))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        sys.exit(1)

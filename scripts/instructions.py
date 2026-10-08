"""Preserve user text while replacing the kit's marked instruction block."""
from pathlib import Path
import io
import sys

BEGIN = '<!-- agent-gates:begin -->'
END = '<!-- agent-gates:end -->'
GLOBAL = '''## agent-gates (machine-wide)
- In any git repo with `.agent-gates/`: follow the repo's AGENTS.md block and GIT_POLICY.md.
- In a repo under my project roots (`~/.agent-gates/roots`) without `.agent-gates/`:
  - if it has no remote and you are about to make or have just made its first commit → run `~/.agent-gates/kit/init.sh <repo> --from-defaults`, then move to your worktree.
  - otherwise → tell the Owner it is not installed; do not install yourself.
'''
PROJECT = '''## Multi-agent rules (agent-gates)

1. Read `GIT_POLICY.md` before any change.
2. Your name is your product name in lowercase (codex, claude, zcode, gemini, cursor, manus, kimi, ...).
3. If your working directory is `{main}`: stop editing here.
   - If `{worktrees}/<name>` does not exist, create it: `{main}/.agent-gates/add_agent.sh <name>`
   - Work only in `{worktrees}/<name>` on branch `agent/<name>`.
4. Never merge into `{branch}`, never push, never run the gate CLI from your own worktree copy.
'''


def update(path, content, check_only=False):
    path = Path(path)
    with path.open(encoding='utf-8', newline='') if path.exists() else io.StringIO('') as stream:
        old = stream.read()
    block = BEGIN + '\n' + content + END if content is not None else ''
    # Replace only our marked region; preserve every byte of the surrounding text.
    start = old.find(BEGIN)
    if start >= 0:
        end = old.find(END, start)
        if end < 0 or old.count(BEGIN) != 1 or old.count(END) != 1:
            raise ValueError('malformed agent-gates block: ' + str(path))
        new = old[:start] + block + old[end + len(END):]
    else:
        if END in old:
            raise ValueError('malformed agent-gates block: ' + str(path))
        new = old + ('\n' if old and not old.endswith('\n') else '') + block + ('\n' if block else '')
    if new != old and not check_only:
        with path.open('w', encoding='utf-8', newline='') as stream:
            stream.write(new)


if __name__ == '__main__':
    check_only = sys.argv[1] == '--check'
    main, worktrees, branch = sys.argv[2:] if check_only else sys.argv[1:]
    content = PROJECT.format(main=main, worktrees=worktrees, branch=branch)
    for name in ('AGENTS.md', 'CLAUDE.md', 'GEMINI.md'):
        update(Path(main) / name, content, check_only=check_only)

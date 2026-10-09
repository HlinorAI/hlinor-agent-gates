"""Hold a cross-platform flock across installer preflight, commit and worktrees."""
import fcntl
import os
from pathlib import Path
import subprocess
import sys

repo, script, *arguments = sys.argv[1:]
common = Path(subprocess.check_output(
    ["git", "-C", repo, "rev-parse", "--path-format=absolute", "--git-common-dir"],
    text=True).strip())
path = common / "agent-gates" / "install.lock"
path.parent.mkdir(parents=True, exist_ok=True)
with path.open("a") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    env = dict(os.environ, AGENT_GATES_INSTALL_LOCK_FD=str(lock.fileno()),
               AGENT_GATES_INSTALL_LOCK_PATH=str(path))
    result = subprocess.run(["bash", script, *arguments], env=env,
                            pass_fds=(lock.fileno(),))
    sys.exit(result.returncode)

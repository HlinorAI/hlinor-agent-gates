#!/usr/bin/env python3
"""Linux enforced mode: phase A provisioning, restricted pushes and diagnostics."""
import argparse
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import shlex
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone

VERSION = "0.4.0"
CODE = Path("/opt/agent-gates")
REPOS = Path("/srv/agent-gates")
STATE = Path("/var/lib/agent-gates")
SUDOERS = Path("/etc/sudoers.d/agent-gates")
OWNER_KEY = Path("/root/.ssh/agent-gates-owner")
EXPECTED_SUDOERS = """Defaults:%agents env_reset, !setenv
%agents     ALL=(agent-gates) NOPASSWD: /opt/agent-gates/bin/agent-gates verify *, /opt/agent-gates/bin/agent-gates merge *, /opt/agent-gates/bin/agent-gates status *, /opt/agent-gates/bin/gate-receive-pack *
agent-gates ALL=(ag-runner)   NOPASSWD: /opt/agent-gates/bin/ag-run *
"""


class Refusal(Exception):
    pass


def deny(code, message):
    raise Refusal("DENY " + code + ": " + message)


def run(*args, data=None, env=None, uid=None):
    command = list(args)
    if uid is not None:
        command = ["runuser", "-u", uid, "--", *command]
    p = subprocess.run(command, input=data, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, env=env)
    if p.returncode:
        deny("SETUP_FAILED", " ".join(p.stderr.splitlines()) or "command failed")
    return p.stdout.strip()


def git(repo, *args):
    return run("git", "-C", str(repo), *args)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def project_name(value):
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", value):
        deny("INVALID_PROJECT", "project must contain lowercase letters, digits, underscores or hyphens")
    return value


def names(value):
    result = value.split(",")
    if not result or len(set(result)) != len(result) or any(
            not re.fullmatch(r"[a-z0-9-]+", name) for name in result):
        deny("INVALID_AGENT", "unique lowercase agent names are required")
    return result


def secure_dir(path, uid, gid, mode):
    path = Path(path)
    if path.is_symlink():
        deny("UNSAFE_PATH", "symlink: " + str(path))
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, uid, gid)
    path.chmod(mode)


def group(name):
    try:
        return grp.getgrnam(name)
    except KeyError:
        run("groupadd", "--system", name)
        return grp.getgrnam(name)


def user(name, group_name, system=False):
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        args = ["useradd", "--gid", group_name, "--shell", "/usr/sbin/nologin" if system else "/bin/bash"]
        args += ["--system", "--no-create-home", "--home-dir", "/nonexistent"] if system else ["--create-home"]
        run(*args, name)
        account = pwd.getpwnam(name)
    if account.pw_uid == 0 or account.pw_gid != grp.getgrnam(group_name).gr_gid:
        deny("UNSAFE_USER", "unexpected UID/group for " + name)
    if system and (account.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false")
                   or account.pw_dir != "/nonexistent"):
        deny("UNSAFE_USER", "system account must have no login/home: " + name)
    for dangerous in ("sudo", "wheel", "root"):
        try:
            if grp.getgrnam(dangerous).gr_gid in os.getgrouplist(name, account.pw_gid):
                deny("UNSAFE_USER", name + " belongs to " + dangerous)
        except KeyError:
            pass
    return account


def metadata(project):
    path = CODE / "projects" / (project_name(project) + ".json")
    if path.is_symlink() or not path.is_file() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
        deny("INVALID_PROJECT", "missing or untrusted project registration")
    return json.loads(path.read_text())


def caller():
    try:
        gate = pwd.getpwnam("agent-gates")
        name = os.environ.get("SUDO_USER", "")
        account = pwd.getpwnam(name)
        agents = grp.getgrnam("agents")
    except KeyError:
        deny("INVALID_IDENTITY", "sudo agent identity required")
    if os.geteuid() != gate.pw_uid or not re.fullmatch(r"agent-[a-z0-9-]+", name):
        deny("INVALID_IDENTITY", "run through sudo as agent-gates")
    if agents.gr_gid not in os.getgrouplist(name, account.pw_gid):
        deny("INVALID_IDENTITY", "caller is not in agents")
    return name


def receive_pack(argv):
    if len(argv) != 1:
        deny("INVALID_ARGUMENT", "one registered bare-repo path required")
    identity = caller()
    raw = Path(argv[0])
    path = raw.resolve()
    if raw.is_symlink() or path.parent != REPOS or path.suffix != ".git":
        deny("INVALID_REPOSITORY", "path must be a registered direct child of /srv/agent-gates")
    info = metadata(path.stem)
    if str(path) != info["bare"] or identity not in info["users"]:
        deny("INVALID_IDENTITY", "caller is not registered for project")
    if sha(path / "hooks/pre-receive") != info["hook_sha256"]:
        deny("HOOK_CHANGED", "pre-receive differs from trusted installation")
    os.umask(0o027)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8",
           "AG_PUSHER": identity}
    os.execve("/usr/bin/git-receive-pack", ["git-receive-pack", str(path)], env)


def pre_receive():
    pusher = os.environ.get("AG_PUSHER", "")
    if os.geteuid() != pwd.getpwnam("agent-gates").pw_uid or not re.fullmatch(r"agent-[a-z0-9-]+", pusher):
        deny("INVALID_IDENTITY", "restricted receive-pack identity required")
    info = metadata(Path.cwd().name.removesuffix(".git"))
    if pusher not in info["users"]:
        deny("INVALID_IDENTITY", "pusher is not registered")
    expected = "refs/heads/agent/" + pusher.removeprefix("agent-")
    for line in sys.stdin:
        parts = line.split()
        if len(parts) != 3 or parts[2] != expected or any(
                not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value) for value in parts[:2]):
            deny("PUSH_FORBIDDEN", "only own agent branch may be pushed")
    return 0


def init(repo_arg, agent_names):
    if sys.platform != "linux" or os.geteuid() != 0:
        deny("ROOT_REQUIRED", "enforce init requires Linux root")
    for command in ("git", "sudo", "visudo", "ssh-keygen", "useradd", "groupadd", "runuser", "pkill"):
        if not shutil.which(command):
            deny("MISSING_DEPENDENCY", command)
    version = re.search(r"(\d+)\.(\d+)", run("git", "--version"))
    if not version or tuple(map(int, version.groups())) < (2, 38):
        deny("GIT_TOO_OLD", "Git 2.38 or later is required")
    repo = Path(repo_arg).resolve()
    project = project_name(repo.name.removesuffix(".git"))
    agent_names = names(agent_names)
    if git(repo, "rev-parse", "--show-toplevel") != str(repo) or git(repo, "branch", "--show-current") != "main":
        deny("INVALID_REPOSITORY", "clean main checkout required")
    if git(repo, "status", "--porcelain"):
        deny("MAIN_DIRTY", "commit or stash before enforcement")
    base = git(repo, "rev-parse", "main")
    manifest_path = CODE / "projects" / (project + ".json")
    if manifest_path.exists():
        info = metadata(project)
        if info["users"] != ["agent-" + name for name in agent_names]:
            deny("ALREADY_INSTALLED", "registered agent list differs")
        if doctor(project):
            deny("NOT_ENFORCED", "repair existing installation; init never overwrites it")
        print("ALREADY ENFORCED " + project)
        return 0
    bare = REPOS / (project + ".git")
    if bare.exists() or any((Path("/home") / ("agent-" + name) / "work" / project).exists() for name in agent_names):
        deny("PATH_EXISTS", "unregistered repository or clone exists")
    if SUDOERS.exists() and SUDOERS.read_text() != EXPECTED_SUDOERS:
        deny("SUDOERS_CONFLICT", "existing sudoers differs; nothing overwritten")
    for parent in (CODE, REPOS, STATE):
        if parent.is_symlink():
            deny("UNSAFE_PATH", "symlink: " + str(parent))
    agents = group("agents")
    gate_group, runner_group = group("agent-gates"), group("ag-runner")
    gate = user("agent-gates", "agent-gates", True)
    runner = user("ag-runner", "ag-runner", True)
    accounts = [user("agent-" + name, "agents") for name in agent_names]
    # agents group contains agent accounts only; primary-group membership counts too.
    members = set(agents.gr_mem) | {p.pw_name for p in pwd.getpwall() if p.pw_gid == agents.gr_gid}
    if any(not re.fullmatch(r"agent-[a-z0-9-]+", name) for name in members):
        deny("UNSAFE_GROUP", "agents contains a non-agent user")
    secure_dir(CODE, 0, 0, 0o755)
    secure_dir(CODE / "bin", 0, 0, 0o755)
    source = Path(__file__).resolve().parent
    hashes = {}
    for name in ("agent-gates", "agent_gates.py", "enforced.py", "gate-receive-pack", "pre-receive", "ag-run"):
        path = source / name
        if not path.is_file() or path.is_symlink():
            deny("MISSING_DEPENDENCY", "trusted kit file missing: " + name)
        target = CODE / "bin" / path.name
        if path.resolve() != target.resolve():
            shutil.copyfile(path, target)
        os.chown(target, 0, 0); target.chmod(0o755)
        hashes[path.name] = sha(target)
    secure_dir(CODE / "projects", 0, 0, 0o755)
    secure_dir(REPOS, gate.pw_uid, agents.gr_gid, 0o750)
    secure_dir(STATE, gate.pw_uid, gate_group.gr_gid, 0o700)
    secure_dir(STATE / "projects", gate.pw_uid, gate_group.gr_gid, 0o700)
    for name in ("receipts", "locks"):
        secure_dir(STATE / "projects" / project / name, gate.pw_uid, gate_group.gr_gid, 0o700)
    os.chown(STATE / "projects" / project, gate.pw_uid, gate_group.gr_gid)
    (STATE / "projects" / project).chmod(0o700)
    runner_lock = STATE / "runner.lock"
    if not runner_lock.exists():
        runner_lock.touch()
    os.chown(runner_lock, gate.pw_uid, gate_group.gr_gid); runner_lock.chmod(0o600)
    key = STATE / "gate_ed25519"
    if not key.exists():
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
    for item, mode in ((key, 0o600), (key.with_suffix(".pub"), 0o644)):
        os.chown(item, gate.pw_uid, gate_group.gr_gid); item.chmod(mode)
    secure_dir(Path("/root/.ssh"), 0, 0, 0o700)
    if not OWNER_KEY.exists():
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(OWNER_KEY))
    OWNER_KEY.chmod(0o600)
    owner_public = run("ssh-keygen", "-y", "-f", str(OWNER_KEY))
    allowed = CODE / "owner_allowed_signers"
    if allowed.exists() and allowed.read_text() != "root " + owner_public + "\n":
        deny("OWNER_KEY_CHANGED", "registered Owner key differs")
    allowed.write_text("root " + owner_public + "\n"); allowed.chmod(0o644); os.chown(allowed, 0, 0)
    # Seed only current main, never refs supplied by an agent or worktree state.
    run("git", "init", "--bare", "--initial-branch=main", str(bare))
    run("git", "--git-dir", str(bare), "fetch", "--no-tags", str(repo), base)
    run("git", "--git-dir", str(bare), "update-ref", "refs/heads/main", base)
    run("git", "--git-dir", str(bare), "config", "core.sharedRepository", "0640")
    hook = bare / "hooks/pre-receive"
    shutil.copyfile(CODE / "bin/pre-receive", hook)
    for directory, dirs, files in os.walk(bare):
        os.chown(directory, gate.pw_uid, agents.gr_gid); os.chmod(directory, 0o2750)
        for filename in files:
            path = Path(directory) / filename
            os.chown(path, gate.pw_uid, agents.gr_gid); path.chmod(0o750 if path == hook else 0o640)
    # Validate before publishing sudo rights, and validate the complete system file set.
    candidate = SUDOERS.with_name(".agent-gates-candidate")
    candidate.write_text(EXPECTED_SUDOERS); candidate.chmod(0o440)
    try:
        run("visudo", "-c", "-f", str(candidate))
        os.replace(candidate, SUDOERS)
        run("visudo", "-c")
    finally:
        candidate.unlink(missing_ok=True)
    info = {"schema": 1, "version": VERSION, "project": project, "bare": str(bare),
            "users": [account.pw_name for account in accounts], "initial_main": base,
            "code_sha256": hashes, "hook_sha256": sha(hook),
            "sudoers_sha256": hashlib.sha256(EXPECTED_SUDOERS.encode()).hexdigest()}
    manifest_path.write_text(json.dumps(info, sort_keys=True) + "\n")
    manifest_path.chmod(0o644); os.chown(manifest_path, 0, 0)
    for account, name in zip(accounts, agent_names):
        home = Path(account.pw_dir)
        secure_dir(home, account.pw_uid, agents.gr_gid, 0o700)
        secure_dir(home / "work", account.pw_uid, agents.gr_gid, 0o700)
        clone = home / "work" / project
        run("git", "config", "--global", "--add", "safe.directory", "/srv/agent-gates/*", uid=account.pw_name)
        # Git also requires safe.directory for the parent before reading bare config.
        run("git", "clone", "--no-local", "--origin", "gate", str(bare), str(clone), uid=account.pw_name)
        run("git", "-C", str(clone), "config", "remote.gate.receivepack",
            "sudo -u agent-gates /opt/agent-gates/bin/gate-receive-pack", uid=account.pw_name)
        run("git", "-C", str(clone), "config", "user.name", name, uid=account.pw_name)
        run("git", "-C", str(clone), "config", "user.email", name + "@local", uid=account.pw_name)
        run("git", "-C", str(clone), "checkout", "-b", "agent/" + name, uid=account.pw_name)
    if doctor(project):
        deny("NOT_ENFORCED", "post-install doctor failed")
    print("ENFORCED " + project)
    return 0


def doctor(project=None):
    failures = 0
    def check(label, condition, detail=""):
        nonlocal failures
        if not condition:
            failures += 1
        print(("OK " if condition else "NOT ENFORCED ") + label + (": " + detail if detail else ""))
    version = re.search(r"(\d+)\.(\d+)", run("git", "--version"))
    check("Git >= 2.38", bool(version and tuple(map(int, version.groups())) >= (2, 38)))
    try:
        gate, runner, agents = pwd.getpwnam("agent-gates"), pwd.getpwnam("ag-runner"), grp.getgrnam("agents")
    except KeyError:
        check("users and group", False); return 1
    check("system identities", gate.pw_uid != 0 and runner.pw_uid != 0 and gate.pw_uid != runner.pw_uid)
    check("system accounts cannot login", all(account.pw_shell in
          ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false") and account.pw_dir == "/nonexistent"
          for account in (gate, runner)))
    all_members = set(agents.gr_mem) | {p.pw_name for p in pwd.getpwall() if p.pw_gid == agents.gr_gid}
    check("agents membership", bool(all_members) and all(re.fullmatch(r"agent-[a-z0-9-]+", name) for name in all_members))
    for name in sorted(all_members):
        account = pwd.getpwnam(name)
        memberships = os.getgrouplist(name, account.pw_gid)
        forbidden = {g.gr_gid for g in grp.getgrall() if g.gr_name in ("sudo", "wheel", "root")}
        check("unprivileged " + name, account.pw_uid != 0 and not forbidden.intersection(memberships))
        home = Path(account.pw_dir)
        check("private home " + name, home.is_dir() and home.stat().st_uid == account.pw_uid and stat.S_IMODE(home.stat().st_mode) == 0o700)
    for path, owner, group_id, mode in ((CODE, 0, 0, 0o755), (REPOS, gate.pw_uid, agents.gr_gid, 0o750),
                                        (STATE, gate.pw_uid, gate.pw_gid, 0o700)):
        try:
            st = path.lstat()
            valid = stat.S_ISDIR(st.st_mode) and (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (owner, group_id, mode)
        except OSError:
            valid = False
        check("ownership/mode " + str(path), valid)
    for directory in (CODE / "bin", CODE / "projects"):
        try:
            st = directory.lstat()
            valid = stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 0o755
        except OSError:
            valid = False
        check("protected directory " + str(directory), valid)
    try:
        st = SUDOERS.lstat()
        check("sudoers ownership/mode", stat.S_ISREG(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o440)
    except OSError:
        check("sudoers ownership/mode", False)
    check("sudoers hash", SUDOERS.is_file() and sha(SUDOERS) == hashlib.sha256(EXPECTED_SUDOERS.encode()).hexdigest())
    projects = [project_name(project)] if project else [path.stem for path in sorted((CODE / "projects").glob("*.json"))]
    check("registered projects", bool(projects))
    for name in projects:
        info = metadata(name)
        for user_name in info["users"]:
            check("registered user " + user_name, user_name in all_members)
        for filename, expected in info["code_sha256"].items():
            path = CODE / "bin" / filename
            try:
                st = path.lstat()
                valid = stat.S_ISREG(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o755 and sha(path) == expected
            except OSError:
                valid = False
            check("gate code " + filename, valid)
        bare = Path(info["bare"])
        for root, dirs, files in os.walk(bare):
            st = Path(root).lstat()
            check("bare dir " + root, stat.S_ISDIR(st.st_mode) and st.st_uid == gate.pw_uid and st.st_gid == agents.gr_gid and stat.S_IMODE(st.st_mode) == 0o2750)
            for file in files:
                path = Path(root) / file; st = path.lstat()
                # Git objects may remove owner write permission; never grant group/world write.
                check("bare file " + str(path), stat.S_ISREG(st.st_mode) and st.st_uid == gate.pw_uid and st.st_gid == agents.gr_gid and not st.st_mode & 0o027 and bool(st.st_mode & stat.S_IRGRP))
        hook = bare / "hooks/pre-receive"
        check("pre-receive hash " + name, hook.is_file() and sha(hook) == info["hook_sha256"])
    try:
        key = STATE / "gate_ed25519"; st = key.lstat()
        check("private gate key", stat.S_ISREG(st.st_mode) and st.st_uid == gate.pw_uid and stat.S_IMODE(st.st_mode) == 0o600)
    except PermissionError:
        check("private gate key metadata", False, "privileged doctor required")
    except OSError:
        check("private gate key", False)
    allowed = CODE / "owner_allowed_signers"
    check("Owner allowed_signers", allowed.is_file() and allowed.stat().st_uid == 0 and not allowed.stat().st_mode & 0o022 and bool(allowed.read_text().strip()))
    processes = run("ps", "-eo", "uid=,comm=,args=").splitlines()
    products = {name.removeprefix("agent-") for name in all_members}
    root_cli = []
    for line in processes:
        parts = line.split(None, 2)
        if len(parts) != 3 or parts[0] != "0":
            continue
        arguments = shlex.split(parts[2])
        executables = [parts[1]] + arguments[:1]
        if arguments and Path(arguments[0]).name.startswith(("python", "node", "bash")):
            executables += arguments[1:2]
        if any(Path(value).name in products for value in executables):
            root_cli.append(line)
    check("no agent CLI running as root", not root_cli)
    busy = any(line.split() and line.split()[0] == str(runner.pw_uid) for line in processes)
    try:
        with (STATE / "runner.lock").open("r") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                check("no idle runner process", not busy)
            except BlockingIOError:
                check("runner currently locked", True)
    except PermissionError:
        check("runner/locks/acceptances metadata", False, "privileged doctor required")
    if os.geteuid() in (0, gate.pw_uid):
        check("lock/acceptance scan available", True)
        # A lock file itself is not stale: flock lifetime, PID liveness and TTL matter.
        for lock in STATE.rglob("*.lock"):
            with lock.open("r") as stream:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    text = lock.read_text().strip()
                    pid = int(text) if text.isdigit() else None
                    check("no stale lock " + str(lock), pid is None or Path("/proc").joinpath(str(pid)).exists())
                except BlockingIOError:
                    check("active lock " + str(lock), True)
        for receipt in STATE.rglob("acceptance-*.json"):
            value = json.loads(receipt.read_text())
            expiry = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
            check("acceptance expiry " + receipt.name, expiry > datetime.now(timezone.utc) + timedelta(hours=2))
    return 1 if failures else 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        if argv and argv[0] == "receive-pack":
            receive_pack(argv[1:]); return 0
        if argv == ["pre-receive"]:
            return pre_receive()
        if argv and argv[0] == "doctor":
            if len(argv) > 2:
                deny("INVALID_ARGUMENT", "doctor accepts at most one project")
            return doctor(argv[1] if len(argv) == 2 else None)
        if argv[:2] == ["enforce", "init"]:
            parser = argparse.ArgumentParser(prog="agent-gates enforce init")
            parser.add_argument("repo")
            parser.add_argument("--agents", default="codex,claude,zcode")
            args = parser.parse_args(argv[2:])
            return init(args.repo, args.agents)
        deny("ENFORCED_PHASE_NOT_IMPLEMENTED", "enforced verify/accept/merge/status are unavailable until phase B")
    except (Refusal, OSError, ValueError, KeyError) as exc:
        message = str(exc)
        if not message.startswith("DENY "):
            message = "DENY NOT_ENFORCED: " + message
        print(" ".join(message.splitlines()), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

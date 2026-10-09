#!/usr/bin/env python3
"""Protected bare-repository gates and the unprivileged test runner (Linux)."""
import argparse
import contextlib
import fcntl
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timedelta, timezone

API = None


def deny(code, text):
    API.deny(code, text)


def canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identifier(record):
    return digest(canonical({k: v for k, v in record.items() if k != "id"}))[:12]


def signing_payload(record):
    return canonical({**{k: v for k, v in record.items() if k != "id"}, "signature": None})


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def clock(text):
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if value.tzinfo is None:
        deny("RECEIPT_TAMPERED", "timezone required")
    return value


def environment():
    return {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_AUTHOR_NAME": "agent-gates", "GIT_AUTHOR_EMAIL": "agent-gates@local",
            "GIT_COMMITTER_NAME": "agent-gates", "GIT_COMMITTER_EMAIL": "agent-gates@local"}


def runner_main(argv):
    """Only the gate may invoke this via the single ag-run sudo rule."""
    runner = pwd.getpwnam("ag-runner")
    if os.geteuid() != runner.pw_uid or os.environ.get("SUDO_USER") != "agent-gates":
        deny("INVALID_IDENTITY", "runner requires sudo from agent-gates")
    if argv == ["kill"]:
        # exec avoids killing the cleanup supervisor itself: pkill excludes its own PID.
        os.execve("/usr/bin/pkill", ["pkill", "-KILL", "-u", str(runner.pw_uid)], environment())
    if not argv or argv[0] not in ("run", "remove") or len(argv) != (3 if argv[0] == "run" else 2):
        deny("INVALID_ARGUMENT", "invalid runner invocation")
    if not re.fullmatch(r"[a-f0-9]{32}", argv[1]):
        deny("INVALID_ARGUMENT", "invalid runner directory token")
    work = Path("/tmp") / ("agent-gates-run-" + argv[1])
    if argv[0] == "remove":
        if work.is_symlink():
            work.unlink()
        elif work.exists():
            if work.lstat().st_uid != runner.pw_uid:
                deny("UNSAFE_PATH", "runner does not own export")
            # Tests own the export and may remove directory permissions.
            work.chmod(0o700)
            for root, dirs, _ in os.walk(work, topdown=True, followlinks=False):
                for name in dirs:
                    directory = Path(root) / name
                    if not directory.is_symlink():
                        directory.chmod(0o700)
            shutil.rmtree(work)
        return 0
    work.mkdir(mode=0o700)  # exclusive; never reuse an attacker-prepared directory
    # Extraction is unprivileged. Reject .git, special files and escaping links.
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|*") as archive:
        for member in archive:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or ".git" in path.parts:
                deny("UNSAFE_ARCHIVE", "unsafe archive path")
            target = work / path
            if not target.resolve().is_relative_to(work):
                deny("UNSAFE_ARCHIVE", "archive escapes export")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(0o700)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as output, archive.extractfile(member) as source:
                    shutil.copyfileobj(source, output)
                target.chmod(0o700 if member.mode & 0o111 else 0o600)
            elif member.issym():
                destination = Path(member.linkname)
                if destination.is_absolute() or not (target.parent / destination).resolve().is_relative_to(work):
                    deny("UNSAFE_ARCHIVE", "archive symlink escapes export")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(member.linkname)
            else:
                deny("UNSAFE_ARCHIVE", "archive contains a special file")
    os.chdir(work)
    env = environment()
    env.update(HOME=str(work), TMPDIR=str(work), USER="ag-runner", LOGNAME="ag-runner")
    with open("/dev/null", "rb") as null:
        os.dup2(null.fileno(), 0)
    os.execve("/bin/bash", ["bash", "-c", argv[2]], env)


class Gates:
    def __init__(self, project, actor):
        self.project, self.actor = API.project_name(project), actor
        self.info = API.metadata(project)
        self.repo = Path(self.info["bare"])
        if self.repo != API.REPOS / (project + ".git") or self.repo.is_symlink():
            deny("INVALID_REPOSITORY", "untrusted bare path")
        if actor != "root" and actor not in self.info["users"]:
            deny("INVALID_IDENTITY", "caller is not registered for project")
        self.directory = API.STATE / "projects" / project / "receipts"
        self.gate = pwd.getpwnam("agent-gates")
        self.cfg = None

    def git_result(self, *args, data=None):
        command = ["/usr/bin/git", "-c", "safe.directory=" + str(self.repo),
                   "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                   "-c", "commit.gpgSign=false", "-c", "diff.external=", "-C", str(self.repo), *args]
        return subprocess.run(command, input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=environment())

    def git(self, *args, data=None):
        result = self.git_result(*args, data=data)
        if result.returncode:
            deny("GIT_FAILED", " ".join(result.stderr.decode(errors="replace").splitlines()))
        return result.stdout.decode().strip()

    def head(self, branch):
        result = self.git_result("rev-parse", "--verify", "refs/heads/" + branch + "^{commit}")
        if result.returncode:
            deny("BRANCH_MOVED", "reviewed branch is missing")
        return result.stdout.decode().strip()

    def policy(self, base):
        raw = self.git("show", base + ":.agent-gates/config")
        values = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.partition("=")
            parts = shlex.split(value, comments=True)
            if not sep or not re.fullmatch(r"[A-Z_]+", key) or len(parts) != 1 or key in values:
                deny("INVALID_POLICY", "invalid main config assignment")
            values[key] = parts[0]
        if not values.get("TEST_CMD") or values.get("MAIN_BRANCH", "main") != "main":
            deny("INVALID_POLICY", "main TEST_CMD is required")
        for key, default in (("TEST_TIMEOUT_SECONDS", "1800"), ("ACCEPT_TTL_HOURS", "24")):
            try:
                values[key] = float(values.get(key, default))
                if not 0 < values[key] < float("inf"):
                    raise ValueError()
            except ValueError:
                deny("INVALID_POLICY", "invalid " + key)
        values.setdefault("POLICY_CHANGES", "deny")
        if values["POLICY_CHANGES"] not in ("deny", "warn"):
            deny("INVALID_POLICY", "invalid POLICY_CHANGES")
        return values

    @contextlib.contextmanager
    def lock(self):
        path = API.STATE / "projects" / self.project / "locks/gates.lock"
        with path.open("a+") as stream:
            os.chmod(path, 0o600)
            if os.geteuid() == 0:
                os.chown(path, self.gate.pw_uid, self.gate.pw_gid)
            fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                self.recover_pending()
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def recover_pending(self):
        for path in self.directory.glob("pending-*.json"):
            try:
                raw = path.read_bytes()
                record = json.loads(raw)
                self.signature(record)
                if (record.get("kind") != "merge" or record.get("project") != self.project
                        or identifier(record) != record.get("id") or canonical(record) != raw
                        or path.stem != "pending-" + record["id"]):
                    raise ValueError()
                committed = self.git_result("merge-base", "--is-ancestor", record["merge_commit"], self.head("main"))
                if committed.returncode:
                    deny("AUDIT_RECOVERY_REQUIRED", "uncommitted merge intent requires Owner recovery")
                target = self.directory / ("merge-" + record["id"] + ".json")
                if target.exists():
                    deny("AUDIT_RECOVERY_REQUIRED", "merge journal conflicts with published receipt")
                os.rename(path, target)
                self.sync_directory()
            except (OSError, ValueError, TypeError, KeyError):
                deny("AUDIT_RECOVERY_REQUIRED", "invalid merge journal requires Owner recovery")

    def merge_tree(self, base, head):
        result = self.git_result("merge-tree", "--write-tree", base, head)
        if result.returncode == 1:
            deny("MERGE_CONFLICT", "merge result contains conflicts")
        if result.returncode:
            deny("GIT_FAILED", "merge-tree failed")
        return result.stdout.decode().splitlines()[0]

    def sign(self, record):
        key = API.OWNER_KEY if record["kind"] == "acceptance" else API.STATE / "gate_ed25519"
        namespace = "agent-gates" if record["kind"] == "acceptance" else "agent-gates-receipt"
        result = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(key), "-n", namespace],
                                input=signing_payload(record), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=environment())
        if result.returncode:
            deny("BAD_SIGNATURE", "receipt signing failed")
        record["signature"] = result.stdout.decode()
        self.signature(record)
        record["id"] = identifier(record)
        return record

    def signature(self, record):
        acceptance = record.get("kind") == "acceptance"
        if not isinstance(record.get("signature"), str):
            deny("BAD_SIGNATURE", "mandatory receipt signature missing")
        if acceptance and record.get("owner") != "root":
            deny("BAD_SIGNATURE", "acceptance must be signed by Owner")
        with tempfile.TemporaryDirectory(prefix="agent-gates-signature-") as temp:
            signature = Path(temp) / "signature"
            signature.write_text(record["signature"])
            if acceptance:
                allowed = API.CODE / "owner_allowed_signers"
                identity, namespace = "root", "agent-gates"
            else:
                allowed = Path(temp) / "allowed_signers"
                allowed.write_text("agent-gates " + (API.STATE / "gate_ed25519.pub").read_text())
                identity, namespace = "agent-gates", "agent-gates-receipt"
            result = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(allowed),
                                     "-I", identity, "-n", namespace, "-s", str(signature)],
                                    input=signing_payload(record), stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=environment())
        if result.returncode:
            deny("BAD_SIGNATURE", "receipt signature verification failed")

    def persist(self, path, data):
        with path.open("xb") as stream:
            os.chmod(path, 0o600)
            if os.geteuid() == 0:
                os.chown(path, self.gate.pw_uid, self.gate.pw_gid)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        self.sync_directory()

    def sync_directory(self):
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def write(self, record):
        self.persist(self.directory / (record["kind"] + "-" + record["id"] + ".json"), canonical(record))

    def load(self, kind, value):
        if not re.fullmatch(r"[a-f0-9]{12}", value):
            deny("RECEIPT_TAMPERED", "invalid receipt id")
        try:
            raw = (self.directory / (kind + "-" + value + ".json")).read_bytes()
            record = json.loads(raw)
            if not isinstance(record, dict):
                raise ValueError()
            # Check signatures first so unsigned/tampered acceptance is BAD_SIGNATURE.
            self.signature(record)
            if (record.get("kind") != kind or record.get("schema") != 1 or record.get("id") != value
                    or identifier(record) != value or canonical(record) != raw
                    or record.get("project") != self.project):
                raise ValueError()
        except (OSError, ValueError, TypeError):
            deny("RECEIPT_TAMPERED", "missing or changed " + kind + " receipt")
        return record, raw

    def bind_policy(self, verification):
        main = self.head("main")
        cfg = self.policy(main)
        if (verification.get("policy_sha") != self.git("rev-parse", main + ":.agent-gates")
                or verification.get("test_cmd_sha256") != digest(cfg["TEST_CMD"].encode())):
            deny("POLICY_CHANGED_SINCE_VERIFY", "main policy or test command changed")
        if verification.get("test_cmd") != cfg["TEST_CMD"]:
            deny("TEST_CMD_MISMATCH", "verification command differs from main policy")
        self.cfg = cfg

    def fresh(self, verification):
        if verification.get("repo") != str(self.repo):
            deny("RECEIPT_TAMPERED", "wrong repository")
        if self.head("main") != verification["base_sha"]:
            deny("MAIN_MOVED", "main changed since verification")
        if self.head(verification["branch"]) != verification["head_sha"]:
            deny("BRANCH_MOVED", "branch changed since verification")

    def verdict(self, verification):
        if verification.get("verdict") != "ACCEPT":
            deny("NOT_ACCEPTED_BY_VERIFIER", "verification verdict is not ACCEPT")
        if verification.get("verifier") == "agent-" + verification.get("author", ""):
            deny("SELF_VERIFICATION", "author cannot verify its own change")
        if (verification.get("branch") != "agent/" + verification.get("author", "")
                or verification.get("verifier") not in self.info["users"]):
            deny("RECEIPT_TAMPERED", "invalid author/verifier identity")

    def changes(self, verification):
        return [path for path in self.git("diff", "--no-ext-diff", "--no-textconv", "--name-only",
                                         "--no-renames", "-z", verification["base_sha"] + "..." +
                                         verification["head_sha"]).split("\0") if path]

    def policy_files(self, verification):
        fixed = {"GIT_POLICY.md", "GIT_POLICY.agent-gates.md", "VERIFIER.md", "VERIFIER.agent-gates.md"}
        patterns = self.cfg.get("POLICY_PATHS", "").split()
        return sorted(path for path in self.changes(verification) if path.startswith(".agent-gates/")
                      or path in fixed or any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns))

    def policy_change_gate(self, verification, allowed):
        paths = self.policy_files(verification)
        if paths and self.cfg["POLICY_CHANGES"] == "deny" and allowed is not True:
            deny("POLICY_CHANGE_REQUIRES_OVERRIDE", "accept requires --allow-policy-change")
        return paths

    def runner(self, *args, **kwargs):
        return subprocess.run(["/usr/bin/sudo", "-n", "-u", "ag-runner", str(API.CODE / "bin/ag-run"), *args],
                              env=environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)

    def cleanup_runner(self, token):
        result = self.runner("kill")
        if result.returncode not in (0, 1):
            deny("RUNNER_CLEANUP_FAILED", "could not kill runner processes")
        result = self.runner("remove", token)
        if result.returncode:
            deny("RUNNER_CLEANUP_FAILED", "could not remove runner export")
        # Zombies cannot execute; ignore them, but deny if any live process remains.
        uid = pwd.getpwnam("ag-runner").pw_uid
        deadline = time.monotonic() + 2
        while True:
            live = False
            for path in Path("/proc").glob("[0-9]*/status"):
                try:
                    text = path.read_text()
                    live |= bool(re.search(r"^Uid:\s+" + str(uid) + r"\s", text, re.M)
                                 and not re.search(r"^State:\s+Z", text, re.M))
                except (FileNotFoundError, ProcessLookupError):
                    pass
            if not live:
                break
            if time.monotonic() >= deadline:
                deny("RUNNER_CLEANUP_FAILED", "live runner process survived cleanup")
            time.sleep(0.02)

    def test(self, commit):
        token = os.urandom(16).hex()
        started, timed_out = time.monotonic(), False
        # Gate controls the timeout/result/log. No result metadata comes from test code.
        with tempfile.TemporaryFile() as archive, tempfile.TemporaryFile() as log:
            exported = subprocess.run(["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-C", str(self.repo),
                                       "archive", "--format=tar", commit], stdout=archive, stderr=subprocess.PIPE,
                                      env=environment())
            if exported.returncode:
                deny("GIT_FAILED", "cannot export verified commit")
            archive.seek(0)
            process = subprocess.Popen(["/usr/bin/sudo", "-n", "-u", "ag-runner", str(API.CODE / "bin/ag-run"),
                                        "run", token, self.cfg["TEST_CMD"]], stdin=archive, stdout=log,
                                       stderr=subprocess.STDOUT, env=environment(), start_new_session=True)
            try:
                try:
                    process.wait(timeout=self.cfg["TEST_TIMEOUT_SECONDS"])
                except subprocess.TimeoutExpired:
                    timed_out = True
                finally:
                    self.cleanup_runner(token)
                    if process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except (ProcessLookupError, PermissionError):
                            pass
                    process.wait(timeout=10)
                log.seek(0)
                output = log.read()
            except BaseException:
                if process.poll() is None:
                    process.terminate()
                raise
        lines = [line for line in output.decode(errors="replace").splitlines() if line.strip()]
        return {"exit": 124 if timed_out else process.returncode, "timed_out": timed_out,
                "summary": lines[-1] if lines else "", "output_sha256": digest(output),
                "seconds": round(time.monotonic() - started, 6)}, output

    def verify(self, args):
        author = args.branch.removeprefix("agent/")
        if "agent-" + author not in self.info["users"]:
            deny("INVALID_IDENTITY", "branch author is not registered")
        if self.actor == "agent-" + author:
            deny("SELF_VERIFICATION", "verifier must differ from author")
        base, head = self.head("main"), self.head(args.branch)
        self.cfg = self.policy(base)
        tree = self.merge_tree(base, head)
        commit = self.git("commit-tree", tree, "-p", base, "-p", head, "-m", "agent-gates temporary verification")
        # One machine-wide lock includes baseline, export and cleanup.
        with (API.STATE / "runner.lock").open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.cleanup_runner(os.urandom(16).hex())
            result, output = self.test(commit)
            baseline, baseline_output = ({"skipped": True}, None)
            if not args.no_baseline:
                baseline, baseline_output = self.test(base)
        record = {"kind": "verification", "schema": 1, "project": self.project, "repo": str(self.repo),
                  "branch": args.branch, "author": author, "verifier": self.actor, "base_sha": base,
                  "head_sha": head, "merge_tree": tree, "test_cmd": self.cfg["TEST_CMD"],
                  "policy_sha": self.git("rev-parse", base + ":.agent-gates"),
                  "test_cmd_sha256": digest(self.cfg["TEST_CMD"].encode()), "result": result, "baseline": baseline,
                  "verdict": "ACCEPT" if result["exit"] == 0 and not baseline.get("timed_out") else "REJECT",
                  "created_at": stamp(), "tool_version": API.VERSION, "signature": None}
        record["policy_files_changed"] = self.policy_files(record)
        changed = self.changes(record)
        record["test_files_changed"] = sorted(path for path in changed if "tests" in Path(path).parts
            or fnmatch.fnmatchcase(Path(path).name, "test_*") or fnmatch.fnmatchcase(Path(path).name, "*_test.*")
            or Path(path).name in {"conftest.py", "pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini", "package.json"})
        lines = 0
        for entry in self.git("diff", "--no-ext-diff", "--no-textconv", "--numstat", "--no-renames", "-z", base + "..." + head).split("\0"):
            parts = entry.split("\t", 2)
            if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
                lines += int(parts[0]) + int(parts[1])
        record["risk"] = (["LARGE_DIFF"] if lines > 1000 else []) + (["LOCKFILE"] if any(
            Path(path).name.endswith(".lock") or Path(path).name in {"package-lock.json", "poetry.lock", "Cargo.lock", "go.sum"}
            for path in changed) else [])
        self.sign(record)
        self.persist(self.directory / (record["id"] + ".log"), output)
        if baseline_output is not None:
            self.persist(self.directory / (record["id"] + ".baseline.log"), baseline_output)
        self.write(record)
        if record["policy_files_changed"]:
            print("WARNING: branch changes gate policy: " + ", ".join(record["policy_files_changed"]), file=sys.stderr)
        print(record["id"])

    def accept(self, args):
        verification, raw = self.load("verification", args.identifier)
        self.verdict(verification)
        self.bind_policy(verification)
        self.fresh(verification)
        paths = self.policy_files(verification)
        print("author: " + verification["author"] + "; verifier: " + verification["verifier"])
        print(self.git("log", "--oneline", verification["base_sha"] + ".." + verification["head_sha"]))
        print(self.git("diff", "--no-ext-diff", "--no-textconv", "--stat", verification["base_sha"], verification["head_sha"]))
        print("test_cmd: " + verification["test_cmd"] + "; tests: " + verification["result"]["summary"])
        print("baseline: " + verification["baseline"].get("summary", "SKIPPED"))
        if paths:
            print("WARNING: branch changes gate policy: " + ", ".join(paths))
        if verification.get("test_files_changed"):
            print("WARNING: branch changes tests: " + ", ".join(verification["test_files_changed"]))
        if verification.get("risk"):
            print("HIGH_RISK: " + ", ".join(verification["risk"]))
        self.policy_change_gate(verification, args.allow_policy_change)
        if not args.yes and input("Accept this verification? Type yes: ").strip() != "yes":
            deny("ACCEPTANCE_NOT_CONFIRMED", "Owner confirmation required")
        self.bind_policy(verification)
        self.fresh(verification)
        record = {"kind": "acceptance", "schema": 1, "project": self.project,
                  "verification_id": verification["id"], "verification_sha256": digest(raw), "owner": "root",
                  "created_at": stamp(), "expires_at": (datetime.now(timezone.utc) +
                      timedelta(hours=self.cfg["ACCEPT_TTL_HOURS"])).isoformat().replace("+00:00", "Z"),
                  "signature": None, "allow_policy_change": args.allow_policy_change}
        self.sign(record)
        self.write(record)
        print(record["id"])

    def check_acceptance(self, value):
        acceptance, _ = self.load("acceptance", value)
        if clock(acceptance["expires_at"]) <= datetime.now(timezone.utc):
            deny("ACCEPTANCE_EXPIRED", "acceptance TTL elapsed")
        verification, raw = self.load("verification", acceptance["verification_id"])
        if digest(raw) != acceptance["verification_sha256"]:
            deny("RECEIPT_TAMPERED", "accepted verification bytes changed")
        self.verdict(verification)
        for path in self.directory.glob("merge-*.json"):
            record, _ = self.load("merge", path.stem.removeprefix("merge-"))
            if record["acceptance_id"] == value:
                deny("RECEIPT_REUSED", "acceptance already merged")
        self.bind_policy(verification)
        self.policy_change_gate(verification, acceptance.get("allow_policy_change", False))
        self.fresh(verification)
        if self.merge_tree(verification["base_sha"], verification["head_sha"]) != verification["merge_tree"]:
            deny("MERGE_RESULT_CHANGED", "computed tree differs from verified tree")
        return acceptance, verification

    def merge(self, args):
        acceptance, verification = self.check_acceptance(args.identifier)
        message = ("agent-gates merge " + verification["branch"] + " (verification: " + verification["id"]
                   + ", acceptance: " + acceptance["id"] + ")")
        commit = self.git("commit-tree", verification["merge_tree"], "-p", verification["base_sha"],
                          "-p", verification["head_sha"], "-m", message)
        record = self.sign({"kind": "merge", "schema": 1, "project": self.project,
                            "acceptance_id": acceptance["id"], "merge_commit": commit,
                            "merged_by": self.actor, "created_at": stamp(), "signature": None})
        # Durable intent precedes the ref change, so a crash never leaves an unaudited merge.
        pending = self.directory / ("pending-" + record["id"] + ".json")
        self.persist(pending, canonical(record))
        transaction = ("start\nverify refs/heads/" + verification["branch"] + " " + verification["head_sha"]
                       + "\nupdate refs/heads/main " + commit + " " + verification["base_sha"] + "\nprepare\ncommit\n")
        result = self.git_result("update-ref", "--stdin", data=transaction.encode())
        if result.returncode:
            pending.unlink()
            self.sync_directory()
            if self.head("main") != verification["base_sha"]:
                deny("MAIN_MOVED", "main changed during atomic merge")
            if self.head(verification["branch"]) != verification["head_sha"]:
                deny("BRANCH_MOVED", "branch changed during atomic merge")
            deny("GIT_FAILED", "atomic ref update failed")
        os.rename(pending, self.directory / ("merge-" + record["id"] + ".json"))
        self.sync_directory()
        print(record["id"])

    def status(self, args):
        for kind in ("verification", "acceptance", "merge"):
            for path in sorted(self.directory.glob(kind + "-*.json")):
                value = path.stem.removeprefix(kind + "-")
                try:
                    record, _ = self.load(kind, value)
                    if kind == "verification":
                        if args.branch and record["branch"] != args.branch:
                            continue
                        self.bind_policy(record)
                        self.fresh(record)
                        state = record["verdict"]
                    elif kind == "acceptance":
                        _, verification = self.check_acceptance(value)
                        if args.branch and verification["branch"] != args.branch:
                            continue
                        state = "VALID"
                    else:
                        state = record["merge_commit"]
                except API.Refusal as exc:
                    state = str(exc).split(":", 1)[0].removeprefix("DENY ")
                print(kind + " " + value + " " + state)


def main(argv, api):
    global API
    API = api
    if argv and argv[0] == "runner":
        return runner_main(argv[1:])
    if "--as" in argv or any(arg.startswith("--as=") for arg in argv):
        deny("INVALID_IDENTITY", "--as is forbidden; enforced identity comes from sudo")
    parser = argparse.ArgumentParser(prog="agent-gates")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("project")
    verify.add_argument("branch")
    verify.add_argument("--no-baseline", action="store_true")
    accept = commands.add_parser("accept")
    accept.add_argument("identifier")
    accept.add_argument("--yes", action="store_true")
    accept.add_argument("--allow-policy-change", action="store_true")
    merge = commands.add_parser("merge")
    merge.add_argument("project")
    merge.add_argument("identifier")
    status = commands.add_parser("status")
    status.add_argument("project")
    status.add_argument("branch", nargs="?")
    args = parser.parse_args(argv)
    if args.command == "accept":
        if os.geteuid() != 0:
            deny("ROOT_REQUIRED", "only Owner root may accept")
        if not re.fullmatch(r"[a-f0-9]{12}", args.identifier):
            deny("RECEIPT_TAMPERED", "invalid receipt id")
        matches = list((API.STATE / "projects").glob("*/receipts/verification-" + args.identifier + ".json"))
        if len(matches) != 1:
            deny("RECEIPT_TAMPERED", "verification missing or ambiguous")
        project, actor = matches[0].parent.parent.name, "root"
    else:
        project, actor = args.project, API.caller()
    if getattr(args, "branch", None) and not re.fullmatch(r"agent/[a-z0-9-]+", args.branch):
        deny("INVALID_ARGUMENT", "branch must match agent/<name>")
    gates = Gates(project, actor)
    os.umask(0o027)
    with gates.lock():
        getattr(gates, args.command)(args)
    return 0

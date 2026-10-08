#!/usr/bin/env python3
"""Local v0.2 governance receipts. Standard library only; no network."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

VERSION = "0.2.0"


class Deny(Exception):
    def __init__(self, code, text):
        self.code, self.text = code, text


class EnvironmentError_(Exception):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def receipt_id(record):
    return digest(canonical({k: v for k, v in record.items() if k != "id"}))[:12]


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def clock(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timezone required")
    return result


def run(args, *, cwd=None, data=None):
    return subprocess.run(args, cwd=cwd, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)


def git(cwd, *args):
    result = run(["git", "-C", str(cwd), *args])
    if result.returncode:
        raise EnvironmentError_(result.stderr.decode(errors="replace").strip())
    return result.stdout.decode().strip()


def git_version():
    result = run(["git", "--version"])
    match = re.search(rb"(\d+)\.(\d+)", result.stdout)
    if not match or tuple(map(int, match.groups())) < (2, 38):
        raise Deny("GIT_TOO_OLD", "Git 2.38 or later is required")


def config():
    here = Path(__file__).resolve().parent
    path = here / "config"
    if not path.is_file():
        raise EnvironmentError_("installed .agent-gates/config not found")
    values = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z_]+", key):
            raise EnvironmentError_("invalid config assignment")
        parts = shlex.split(value, comments=True)
        if len(parts) != 1:
            raise EnvironmentError_("invalid config value for " + key)
        values[key] = parts[0]
    for key in ("MAIN_BRANCH", "TEST_CMD", "OWNER_NAME"):
        if not values.get(key):
            raise EnvironmentError_("missing config " + key)
    try:
        values["ACCEPT_TTL_HOURS"] = float(values.get("ACCEPT_TTL_HOURS", "24"))
        if not 0 < values["ACCEPT_TTL_HOURS"] < float("inf"):
            raise ValueError()
    except ValueError:
        raise EnvironmentError_("invalid ACCEPT_TTL_HOURS")
    main = None
    for block in git(here, "worktree", "list", "--porcelain").split("\n\n"):
        rows = block.splitlines()
        if "branch refs/heads/" + values["MAIN_BRANCH"] in rows:
            main = Path(rows[0].removeprefix("worktree ")).resolve()
    if main is None:
        raise EnvironmentError_("main branch has no checkout")
    common = Path(git(main, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    values["repo"], values["receipts"] = main, common / "agent-gates" / "receipts"
    return values


class Gates:
    def __init__(self, cfg):
        self.cfg = cfg
        self.repo, self.directory = cfg["repo"], cfg["receipts"]
        self.directory.mkdir(parents=True, exist_ok=True)

    @contextlib.contextmanager
    def lock(self):
        # Serialize CLI state transitions across all worktrees of this repository.
        with (self.directory.parent / "lock").open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def clean(self):
        if git(self.repo, "status", "--porcelain"):
            raise Deny("MAIN_DIRTY", "main working tree is not clean")

    def head(self, branch):
        result = run(["git", "-C", str(self.repo), "rev-parse", "--verify",
                      "refs/heads/" + branch + "^{commit}"])
        if result.returncode:
            raise Deny("BRANCH_MOVED", "reviewed branch is missing")
        return result.stdout.decode().strip()

    def merge_tree(self, base, head):
        result = run(["git", "-C", str(self.repo), "merge-tree", "--write-tree", base, head])
        if result.returncode == 1:
            raise Deny("MERGE_CONFLICT", "merge result contains conflicts")
        if result.returncode:
            raise EnvironmentError_(result.stderr.decode(errors="replace").strip())
        return result.stdout.decode().splitlines()[0]

    def write(self, record):
        record = dict(record)
        record["id"] = receipt_id(record)
        path = self.directory / (record["kind"] + "-" + record["id"] + ".json")
        # Exclusive creation prevents overwriting evidence.
        with path.open("xb") as stream:
            stream.write(canonical(record))
            stream.flush()
            os.fsync(stream.fileno())
        return record

    def load(self, kind, identifier):
        if not re.fullmatch(r"[a-f0-9]{12}", identifier):
            raise Deny("RECEIPT_TAMPERED", "invalid receipt id")
        path = self.directory / (kind + "-" + identifier + ".json")
        try:
            raw = path.read_bytes()
            record = json.loads(raw)
            if (not isinstance(record, dict) or record.get("kind") != kind
                    or record.get("schema") != 1 or record.get("id") != identifier
                    or receipt_id(record) != identifier or canonical(record) != raw):
                raise ValueError()
            required = {
                "verification": ("repo", "branch", "author", "verifier", "base_sha",
                                 "head_sha", "merge_tree", "verdict", "result", "baseline"),
                "acceptance": ("verification_id", "verification_sha256", "owner",
                               "created_at", "expires_at", "signature"),
                "merge": ("acceptance_id", "merge_commit", "merged_by", "created_at"),
            }[kind]
            if any(key not in record for key in required):
                raise ValueError()
        except (OSError, ValueError, TypeError):
            raise Deny("RECEIPT_TAMPERED", "missing or changed " + kind + " receipt")
        return record, raw

    def fresh(self, verification):
        if verification["repo"] != str(self.repo):
            raise Deny("RECEIPT_TAMPERED", "verification belongs to another repository")
        if git(self.repo, "rev-parse", "HEAD") != verification["base_sha"]:
            raise Deny("MAIN_MOVED", "main changed since verification")
        if self.head(verification["branch"]) != verification["head_sha"]:
            raise Deny("BRANCH_MOVED", "branch changed since verification")

    def verdict(self, verification):
        if verification["verdict"] != "ACCEPT":
            raise Deny("NOT_ACCEPTED_BY_VERIFIER", "verification verdict is not ACCEPT")
        if verification["author"] == verification["verifier"]:
            raise Deny("SELF_VERIFICATION", "author cannot verify its own change")
        if verification["branch"] != "agent/" + verification["author"]:
            raise Deny("RECEIPT_TAMPERED", "author does not match branch")

    def test(self, commit):
        with tempfile.TemporaryDirectory(prefix="agent-gates-test-") as temp:
            worktree = Path(temp) / "checkout"
            git(self.repo, "worktree", "add", "--detach", str(worktree), commit)
            try:
                started = time.monotonic()
                completed = subprocess.run(self.cfg["TEST_CMD"], shell=True,
                                           executable="/bin/bash", cwd=worktree,
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                output = completed.stdout
                lines = [line for line in output.decode(errors="replace").splitlines() if line.strip()]
                result = {"exit": completed.returncode, "summary": lines[-1] if lines else "",
                          "output_sha256": digest(output),
                          "seconds": round(time.monotonic() - started, 6)}
                return result, output
            finally:
                # Only the throwaway test checkout is removed, including generated files.
                git(self.repo, "worktree", "remove", "--force", str(worktree))

    def verify(self, args):
        author = args.branch.removeprefix("agent/")
        if args.verifier == author:
            raise Deny("SELF_VERIFICATION", "verifier must differ from author")
        self.clean()
        base, head = git(self.repo, "rev-parse", "HEAD"), self.head(args.branch)
        tree = self.merge_tree(base, head)
        commit = git(self.repo, "commit-tree", tree, "-p", base, "-p", head,
                     "-m", "agent-gates temporary verification")
        result, output = self.test(commit)
        baseline, baseline_output = ({"skipped": True}, None)
        if not args.no_baseline:
            baseline, baseline_output = self.test(base)
        record = {
            "kind": "verification", "schema": 1, "repo": str(self.repo),
            "branch": args.branch, "author": author, "verifier": args.verifier,
            "base_sha": base, "head_sha": head, "merge_tree": tree,
            "test_cmd": self.cfg["TEST_CMD"], "result": result, "baseline": baseline,
            "verdict": "ACCEPT" if result["exit"] == 0 else "REJECT",
            "created_at": stamp(), "tool_version": VERSION,
        }
        record["id"] = receipt_id(record)
        (self.directory / (record["id"] + ".log")).write_bytes(output)
        if baseline_output is not None:
            (self.directory / (record["id"] + ".baseline.log")).write_bytes(baseline_output)
        self.write(record)
        print(record["id"])

    @staticmethod
    def signing_payload(record):
        # Sign acceptance fields before adding signature/id; merge reconstructs the same bytes.
        return canonical({**{k: v for k, v in record.items() if k != "id"}, "signature": None})

    def signature(self, record):
        enabled = self.cfg.get("OWNER_SIGNING_KEY") or record.get("signature") is not None
        if not enabled:
            return
        signature = record.get("signature")
        if not isinstance(signature, str) or record.get("owner") != self.cfg["OWNER_NAME"]:
            raise Deny("BAD_SIGNATURE", "Owner signature is missing or invalid")
        with tempfile.TemporaryDirectory(prefix="agent-gates-signature-") as temp:
            path = Path(temp) / "signature"
            path.write_text(signature)
            result = run(["ssh-keygen", "-Y", "verify", "-f",
                          str(self.repo / ".agent-gates" / "allowed_signers"),
                          "-I", record["owner"], "-n", "agent-gates", "-s", str(path)],
                         data=self.signing_payload(record))
        if result.returncode:
            raise Deny("BAD_SIGNATURE", "Owner signature verification failed")

    def accept(self, args):
        verification, raw = self.load("verification", args.identifier)
        self.verdict(verification)
        self.fresh(verification)
        print("author: " + verification["author"] + "; verifier: " + verification["verifier"])
        print(git(self.repo, "log", "--oneline", verification["base_sha"] + ".." + verification["head_sha"]))
        print(git(self.repo, "diff", "--stat", verification["base_sha"], verification["head_sha"]))
        print("tests: " + verification["result"]["summary"])
        print("baseline: " + verification["baseline"].get("summary", "SKIPPED"))
        if not args.yes and input("Accept this verification? Type yes: ").strip() != "yes":
            raise EnvironmentError_("acceptance not confirmed")
        # Owner may take time at the prompt; bind to current refs again before writing.
        self.fresh(verification)
        record = {"kind": "acceptance", "schema": 1,
                  "verification_id": verification["id"], "verification_sha256": digest(raw),
                  "owner": self.cfg["OWNER_NAME"], "created_at": stamp(),
                  "expires_at": (datetime.now(timezone.utc) +
                                 timedelta(hours=self.cfg["ACCEPT_TTL_HOURS"])).isoformat().replace("+00:00", "Z"),
                  "signature": None}
        key = self.cfg.get("OWNER_SIGNING_KEY")
        if key:
            signed = run(["ssh-keygen", "-Y", "sign", "-f", key, "-n", "agent-gates"],
                         data=self.signing_payload(record))
            if signed.returncode:
                raise EnvironmentError_("ssh-keygen could not sign acceptance")
            record["signature"] = signed.stdout.decode()
            self.signature(record)
        print(self.write(record)["id"])

    def check_acceptance(self, identifier):
        # Check signed data before hash validation too: editing signed acceptance is BAD_SIGNATURE.
        path = self.directory / ("acceptance-" + identifier + ".json")
        if re.fullmatch(r"[a-f0-9]{12}", identifier) and path.is_file():
            try:
                record = json.loads(path.read_bytes())
                if isinstance(record, dict):
                    self.signature(record)
            except (ValueError, TypeError):
                raise Deny("RECEIPT_TAMPERED", "invalid acceptance")
        acceptance, _ = self.load("acceptance", identifier)
        self.signature(acceptance)
        try:
            expired = clock(acceptance["expires_at"]) <= datetime.now(timezone.utc)
        except (ValueError, TypeError, AttributeError):
            raise Deny("RECEIPT_TAMPERED", "invalid acceptance expiry")
        if expired:
            raise Deny("ACCEPTANCE_EXPIRED", "acceptance TTL has elapsed")
        verification, raw = self.load("verification", acceptance["verification_id"])
        if digest(raw) != acceptance["verification_sha256"]:
            raise Deny("RECEIPT_TAMPERED", "accepted verification bytes changed")
        self.verdict(verification)
        # Replay is diagnosed before freshness: a successful merge necessarily moves main.
        for path in self.directory.glob("merge-*.json"):
            merged, _ = self.load("merge", path.stem.removeprefix("merge-"))
            if merged["acceptance_id"] == identifier:
                raise Deny("RECEIPT_REUSED", "acceptance was already used")
        self.fresh(verification)
        self.clean()
        if self.merge_tree(verification["base_sha"], verification["head_sha"]) != verification["merge_tree"]:
            raise Deny("MERGE_RESULT_CHANGED", "computed merge result changed")
        return acceptance, verification

    def merge(self, args):
        acceptance, verification = self.check_acceptance(args.identifier)
        message = ("agent-gates merge " + verification["branch"] +
                   " (verification: " + verification["id"] +
                   ", acceptance: " + acceptance["id"] + ")")
        result = run(["git", "-C", str(self.repo), "merge", "--no-ff", "--no-commit", verification["head_sha"]])
        pending = (Path(git(self.repo, "rev-parse", "--absolute-git-dir")) / "MERGE_HEAD").exists()
        if result.returncode:
            if pending:
                git(self.repo, "merge", "--abort")
            raise Deny("MERGE_CONFLICT", "merge could not be prepared")
        if not pending:
            # Git considers an already contained head up-to-date, so cannot create --no-ff commit.
            raise EnvironmentError_("branch is already contained in main")
        try:
            if (git(self.repo, "rev-parse", "HEAD") != verification["base_sha"] or
                    git(self.repo, "write-tree") != verification["merge_tree"]):
                raise Deny("MERGE_RESULT_CHANGED", "prepared merge tree differs from verified tree")
            git(self.repo, "commit", "-m", message)
        except Exception:
            if pending and (Path(git(self.repo, "rev-parse", "--absolute-git-dir")) / "MERGE_HEAD").exists():
                git(self.repo, "merge", "--abort")
            raise
        commit = git(self.repo, "rev-parse", "HEAD")
        if git(self.repo, "rev-parse", "HEAD^{tree}") != verification["merge_tree"]:
            # Undo only this merge from a previously clean main, including hook changes.
            git(self.repo, "reset", "--merge", verification["base_sha"])
            raise Deny("MERGE_RESULT_CHANGED", "committed tree differs; merge rolled back")
        record = self.write({"kind": "merge", "schema": 1, "acceptance_id": acceptance["id"],
                             "merge_commit": commit, "merged_by": os.environ.get("USER", "unknown"),
                             "created_at": stamp()})
        print(record["id"])

    def status(self, args):
        for path in sorted(self.directory.glob("verification-*.json")):
            identifier = path.stem.removeprefix("verification-")
            try:
                verification, _ = self.load("verification", identifier)
                if args.branch and verification["branch"] != args.branch:
                    continue
                self.verdict(verification)
                self.fresh(verification)
                state = "VALID"
            except Deny as exc:
                state = exc.code
            print("verification " + identifier + " " + state)
        for path in sorted(self.directory.glob("acceptance-*.json")):
            identifier = path.stem.removeprefix("acceptance-")
            try:
                acceptance, _ = self.load("acceptance", identifier)
                verification, _ = self.load("verification", acceptance["verification_id"])
                if args.branch and verification["branch"] != args.branch:
                    continue
                self.check_acceptance(identifier)
                state = "VALID"
            except Deny as exc:
                state = exc.code
            try:
                unsigned = json.loads(path.read_bytes()).get("signature") is None
            except (OSError, ValueError, AttributeError):
                unsigned = False
            print("acceptance " + identifier + " " + state + (" UNSIGNED" if unsigned else ""))
        for path in sorted(self.directory.glob("merge-*.json")):
            identifier = path.stem.removeprefix("merge-")
            record, _ = self.load("merge", identifier)
            acceptance, _ = self.load("acceptance", record["acceptance_id"])
            verification, _ = self.load("verification", acceptance["verification_id"])
            if not args.branch or verification["branch"] == args.branch:
                print("merge " + identifier + " " + record["merge_commit"])


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("branch")
    verify.add_argument("--as", dest="verifier", required=True)
    verify.add_argument("--no-baseline", action="store_true")
    accept = commands.add_parser("accept")
    accept.add_argument("identifier")
    accept.add_argument("--yes", action="store_true")
    merge = commands.add_parser("merge")
    merge.add_argument("identifier")
    status = commands.add_parser("status")
    status.add_argument("branch", nargs="?")
    args = parser.parse_args()
    if args.command in ("verify", "status") and (
            getattr(args, "branch", None) is not None and
            not re.fullmatch(r"agent/[a-z0-9-]+", args.branch)):
        parser.error("branch must match agent/<name>")
    try:
        git_version()
        gates = Gates(config())
        with gates.lock():
            getattr(gates, args.command)(args)
        return 0
    except Deny as exc:
        print("DENY " + exc.code + ": " + " ".join(exc.text.splitlines()))
        return 1
    except (EnvironmentError_, OSError, ValueError, KeyError, TypeError, EOFError) as exc:
        print("ERROR: " + " ".join(str(exc).splitlines()), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Local v0.2 governance receipts. Standard library only; no network."""
import argparse
import contextlib
import fcntl
import fnmatch
import hashlib
import importlib.util
import stat
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone

sys.dont_write_bytecode = True
VERSION = "0.6.0"


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
    # Git's primary checkout is the installed main repo; never bootstrap policy
    # from the script's worktree-local config.
    worktrees = git(here, "worktree", "list", "--porcelain").split("\n\n")
    primary = worktrees[0].splitlines()
    main = Path(primary[0].removeprefix("worktree ")).resolve()
    path = main / ".agent-gates" / "config"
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
    values.setdefault("POLICY_CHANGES", "deny")
    if values["POLICY_CHANGES"] not in ("deny", "warn"):
        raise EnvironmentError_("invalid POLICY_CHANGES")
    try:
        values["TEST_TIMEOUT_SECONDS"] = float(values.get("TEST_TIMEOUT_SECONDS", "1800"))
        if not 0 < values["TEST_TIMEOUT_SECONDS"] < float("inf"):
            raise ValueError()
    except ValueError:
        raise EnvironmentError_("invalid TEST_TIMEOUT_SECONDS")
    if "branch refs/heads/" + values["MAIN_BRANCH"] not in primary:
        raise EnvironmentError_("primary checkout is not the configured main branch")
    common = Path(git(main, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    values["repo"], values["receipts"] = main, common / "agent-gates" / "receipts"
    return values


"""Shared stdlib audit chain and read paths. Callers hold the project gate lock."""
import hashlib
import json
import os
from pathlib import Path
import re
from datetime import datetime, timedelta, timezone

ZERO = '0' * 64


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def clock(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('timezone required')
    return result


class Broken(Exception):
    def __init__(self, seq, text):
        self.seq = seq
        super().__init__('seq %s: %s' % (seq, text))


class Audit:
    def __init__(self, gates):
        self.gates = gates
        self.path = gates.directory / 'audit.jsonl'

    def scan(self):
        rows, head = [], ZERO
        raw = self.path.read_bytes() if self.path.exists() else b''
        for index, line in enumerate(raw.splitlines(keepends=True), 1):
            try:
                row = json.loads(line)
                unsigned = {k: v for k, v in row.items() if k != 'hash'}
                if (type(row.get('seq')) is not int or row['seq'] != index or row.get('prev') != head
                        or row.get('hash') != digest(canonical(unsigned)) or canonical(row) + b'\n' != line
                        or any(k not in row for k in ('at', 'event', 'actor', 'project', 'branch', 'receipt', 'result'))):
                    raise ValueError('invalid canonical line, sequence, predecessor or hash')
                clock(row['at'])
            except (ValueError, TypeError, AttributeError):
                raise Broken(index, 'invalid canonical line, sequence, predecessor or hash')
            rows.append(row)
            head = row['hash']
        return rows, head

    def prepare(self, record):
        rows, head = self.scan()
        record['audit_seq'], record['audit_prev'] = len(rows) + 1, head
        return record

    def append(self, event, *, branch='', receipt='', result='OK', actor=None, **extra):
        try:
            rows, head = self.scan()
            row = dict(seq=len(rows)+1, at=stamp(), event=event,
                       actor=actor or self.gates.audit_actor(), project=self.gates.audit_project(),
                       branch=branch, receipt=receipt, result=result, prev=head, **extra)
            row['hash'] = digest(canonical(row))
            with self.path.open('ab') as stream:
                os.chmod(self.path, 0o600)
                self.gates.audit_ownership(self.path)
                stream.write(canonical(row) + b'\n')
                stream.flush()
                os.fsync(stream.fileno())
            fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            return row
        except Broken as exc:
            self.gates.audit_deny('AUDIT_BROKEN', str(exc))
        except OSError:
            self.gates.audit_deny('AUDIT_UNAVAILABLE', 'audit append could not be made durable')

    def receipt_event(self, record, recovered=False):
        event = {'verification': 'verify', 'acceptance': 'accept', 'merge': 'merge'}[record['kind']]
        fields = self.gates.audit_fields(record)
        fields['receipt'] = record['id']
        fields['result'] = record.get('verdict', 'OK')
        if recovered:
            rows, head = self.scan()
            if record['audit_seq'] != len(rows)+1 or record['audit_prev'] != head:
                self.gates.audit_deny('AUDIT_BROKEN', 'seq %s: recovery slot occupied or predecessor differs' % record['audit_seq'])
            fields.update(original_event=event, original_created_at=record['created_at'],
                          original_audit_seq=record['audit_seq'], original_audit_prev=record['audit_prev'])
        return self.append('recovered' if recovered else event, **fields)

    def records(self, strict=True):
        for kind in ('verification', 'acceptance', 'merge'):
            for path in sorted(self.gates.directory.glob(kind+'-*.json')):
                # Delegate hash/signature validation to the existing gate.
                try:
                    yield self.gates.load(kind, path.stem.removeprefix(kind+'-'))[0]
                except self.gates.audit_refusal():
                    if strict:
                        raise

    @staticmethod
    def matched(record, rows):
        for row in rows:
            if row['receipt'] != record['id']:
                continue
            if row['event'] == 'recovered':
                if (row['seq'] == record['audit_seq'] and row['prev'] == record['audit_prev']
                        and row.get('original_audit_seq') == record['audit_seq']
                        and row.get('original_audit_prev') == record['audit_prev']):
                    return True
            elif row['event'] == {'verification':'verify', 'acceptance':'accept', 'merge':'merge'}[record['kind']]:
                if row['seq'] == record['audit_seq'] and row['prev'] == record['audit_prev']:
                    return True
        return False

    def invalidated(self, rows=None):
        if rows is None:
            rows, _ = self.scan()
        return {identifier for row in rows if row['event']=='reseal'
                for identifier in row.get('invalidated_receipts', [])}

    def require_valid(self, record):
        if record['id'] in self.invalidated():
            self.gates.audit_deny('RECEIPT_INVALIDATED', 'receipt was invalidated by Owner reseal')

    def verify(self, expect_head=None, expect_seq=None):
        rows, head = self.scan()
        if expect_head is not None and head != expect_head:
            raise Broken(len(rows)+1, 'external head mismatch')
        if expect_seq is not None and len(rows) != expect_seq:
            raise Broken(min(len(rows), expect_seq)+1, 'external sequence mismatch')
        invalidated = self.invalidated(rows)
        for record in self.records():
            if record['id'] in invalidated:
                continue
            if 'audit_seq' not in record:  # v0.5 evidence stays immutable and readable
                continue
            if type(record['audit_seq']) is not int or record['audit_seq'] < 1:
                raise Broken(1, 'invalid receipt audit sequence')
            if not self.matched(record, rows):
                raise Broken(record['audit_seq'], 'receipt %s has no matching event' % record['id'])
        return rows, head

    def recover(self):
        try:
            rows, _ = self.scan()
        except Broken as exc:
            self.gates.audit_deny('AUDIT_BROKEN', str(exc))
        except OSError:
            self.gates.audit_deny('AUDIT_UNAVAILABLE', 'audit log unavailable')
        invalidated = self.invalidated(rows)
        pending = []
        for kind in ('verification', 'acceptance', 'merge'):
            for path in sorted(self.gates.directory.glob(kind+'-*.json')):
                try:
                    record = self.gates.load(kind, path.stem.removeprefix(kind+'-'))[0]
                except self.gates.audit_refusal():
                    # Preserve the existing signature/tamper DENY from the requested operation.
                    continue
                if record['id'] not in invalidated and 'audit_seq' in record and not self.matched(record, rows):
                    if (type(record['audit_seq']) is not int or record['audit_seq'] < 1
                            or not isinstance(record.get('audit_prev'), str)
                            or not re.fullmatch(r'[a-f0-9]{64}',record['audit_prev'])):
                        self.gates.audit_deny('AUDIT_BROKEN', 'invalid receipt audit anchor')
                    pending.append(record)
        for record in sorted(pending, key=lambda r: (r['audit_seq'], r['created_at'], r['id'])):
            self.receipt_event(record, recovered=True)

    def reseal(self, reason):
        if not reason.strip():
            self.gates.audit_deny('INVALID_ARGUMENT', 'reseal requires a reason')
        raw = self.path.read_bytes() if self.path.exists() else b''
        try:
            rows, _ = self.scan()
            prefix = raw
        except Broken as exc:
            prefix = b''.join(raw.splitlines(keepends=True)[:exc.seq-1])
        valid_rows = [json.loads(line) for line in prefix.splitlines()]
        prior_invalidated = self.invalidated(valid_rows)
        invalidated = set()
        for kind in ('verification', 'acceptance', 'merge', 'pending'):
            for path in self.gates.directory.glob(kind+'-*.json'):
                record = json.loads(path.read_bytes())
                if (record.get('id') not in prior_invalidated and 'audit_seq' in record
                        and not self.matched(record, valid_rows)):
                    invalidated.add(record['id'])
        tail = raw[len(prefix):]
        tail_hash = digest(tail)
        # Keep every discarded byte, including a partially written line, as permanent evidence.
        saved = self.gates.directory / ('audit-tail-'+tail_hash+'.log')
        if tail and not saved.exists():
            with saved.open('xb') as stream:
                os.chmod(saved, 0o600)
                self.gates.audit_ownership(saved)
                stream.write(tail); stream.flush(); os.fsync(stream.fileno())
        temporary = self.path.with_name('audit.reseal.tmp')
        try:
            with temporary.open('xb') as stream:
                os.chmod(temporary, 0o600)
                self.gates.audit_ownership(temporary)
                stream.write(prefix); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            self.append('reseal', reason=reason, discarded_tail_sha256=tail_hash,
                        discarded_tail_file=saved.name if tail else '',
                        invalidated_receipts=sorted(invalidated))
        except OSError:
            self.gates.audit_deny('AUDIT_UNAVAILABLE', 'reseal could not be made durable')
        finally:
            temporary.unlink(missing_ok=True)


class Observability:
    def audit_project(self):
        return getattr(self, 'project', self.repo.name)

    def audit_actor(self):
        return getattr(self, 'actor', os.environ.get('USER', 'unknown'))

    def audit_ownership(self, path):
        gate = getattr(self, 'gate', None)
        if gate is not None and os.geteuid() == 0:
            os.chown(path, gate.pw_uid, gate.pw_gid)

    def audit_fields(self, record):
        branch = record.get('branch', '')
        if record['kind'] == 'acceptance':
            branch = self.load('verification', record['verification_id'])[0]['branch']
        elif record['kind'] == 'merge':
            acceptance = self.load('acceptance', record['acceptance_id'])[0]
            branch = self.load('verification', acceptance['verification_id'])[0]['branch']
        actor = record.get('verifier', record.get('owner', record.get('merged_by', self.audit_actor())))
        return dict(branch=branch, actor=actor)

    def audit(self, args):
        if args.audit_command == 'reseal':
            self.audit_owner()
            Audit(self).reseal(args.reason)
            Audit(self).recover()
        try:
            rows, head = Audit(self).verify(getattr(args, 'expect_head', None), getattr(args, 'expect_seq', None))
        except Broken as exc:
            self.audit_deny('AUDIT_BROKEN', str(exc))
        print('OK %s %s' % (len(rows), head))

    def audit_report_break(self):
        try:
            Audit(self).verify()
        except (Broken, OSError, self.audit_refusal()) as exc:
            import sys
            print('AUDIT_BROKEN: '+str(exc), file=sys.stderr)

    def history(self, args):
        self.audit_report_break()
        try:
            rows, _ = Audit(self).scan()
        except Broken as exc:
            # Show the valid prefix, without repairing or writing anything.
            raw = Audit(self).path.read_bytes()
            rows = [json.loads(line) for line in raw.splitlines()[:exc.seq-1]]
        threshold = None
        if args.since:
            match = re.fullmatch(r'(\d+)([dhm])', args.since)
            if not match:
                self.audit_deny('INVALID_ARGUMENT', '--since must use d, h or m')
            threshold = datetime.now(timezone.utc)-timedelta(seconds=int(match[1])*{'d':86400,'h':3600,'m':60}[match[2]])
        rows = [r for r in rows if (not args.branch or r['branch'] == args.branch)
                and (threshold is None or clock(r['at']) >= threshold)]
        if args.json:
            print(canonical(rows).decode())
        else:
            for r in rows:
                print('%s %s %s %s %s %s' % tuple(r[k] for k in ('at','event','branch','actor','receipt','result')))

    def summaries(self):
        records = list(Audit(self).records(strict=False))
        vs = [r for r in records if r['kind']=='verification']
        accepts = [r for r in records if r['kind']=='acceptance']
        used = {r['acceptance_id'] for r in records if r['kind']=='merge'}
        used_vs = {r['verification_id'] for r in accepts if r['id'] in used}
        invalidated = Audit(self).invalidated()
        main = self.head(self.audit_main())
        rows = []
        for branch in self.audit_git('for-each-ref', '--format=%(refname:short)', 'refs/heads/agent/').splitlines():
            candidates = [r for r in vs if r['branch']==branch]
            v = max(candidates, key=lambda r:(r['created_at'],r['id']), default=None)
            candidates = [r for r in accepts if v and r['verification_id']==v['id']]
            a = max(candidates, key=lambda r:(r['created_at'],r['id']), default=None)
            verification, acceptance = 'NONE', 'NONE'
            if v:
                if v['id'] in invalidated: verification = 'INVALIDATED'
                elif v['id'] in used_vs: verification = 'MERGED'
                elif self.head(branch)!=v['head_sha']: verification='STALE: BRANCH_MOVED'
                elif main!=v['base_sha']: verification='STALE: MAIN_MOVED'
                else: verification=v['verdict']
            if a:
                left=(clock(a['expires_at'])-datetime.now(timezone.utc)).total_seconds()
                if a['id'] in invalidated or v['id'] in invalidated: acceptance='INVALIDATED'
                elif a['id'] in used: acceptance='USED'
                elif left<=0: acceptance='EXPIRED'
                elif left<7200: acceptance='EXPIRING (<2h)'
                else: acceptance='VALID (expires in %sh)' % max(1, int(left//3600))
            ahead=int(self.audit_git('rev-list','--count', main+'..'+self.head(branch)))
            if verification.startswith('STALE') or verification=='INVALIDATED': next_step='re-verify'
            elif not ahead or verification=='MERGED': next_step='—'
            elif verification in ('NONE','REJECT'): next_step='verify'
            elif acceptance in ('NONE','EXPIRED'): next_step='accept'
            else: next_step='merge'
            rows.append(dict(branch=branch,author=branch.removeprefix('agent/'),ahead=ahead,
                             verification=verification,acceptance=acceptance,next_step=next_step))
        return rows

    def status_all(self, args):
        if getattr(args, 'notify', False):
            self.audit_owner()
            self.audit_deny('INVALID_ARGUMENT', 'notifications are not installed in phase A')
        self.audit_report_break()
        rows=self.summaries()
        if args.json: print(canonical(rows).decode())
        else:
            for r in rows: print('{branch} {author} ahead={ahead} {verification} {acceptance} {next_step}'.format(**r))

    def list_agents(self, args):
        self.audit_report_break()
        rows=self.summaries()
        paths=self.audit_paths()
        known={row['branch'] for row in rows}
        for branch,path in paths.items():
            if branch.startswith('agent/') and branch not in known:
                rows.append(dict(branch=branch, author=branch.removeprefix('agent/'), ahead=0,
                                 verification='NONE', acceptance='NONE', next_step='verify'))
        for row in rows:
            row['name']=row['author']
            row['path']=paths.get(row['branch'])
            ref=row['branch'] if row['branch'] in known else self.audit_main()
            row['last_commit_at']=self.audit_git('show','-s','--format=%cI',ref)
        if args.json: print(canonical(rows).decode())
        else:
            for r in rows: print('{name} {path} {branch} {last_commit_at} {verification}'.format(**r))

    def check_merge(self, args):
        Audit(self).scan()  # broken log cannot accept a check event
        try:
            _, v=self.check_acceptance(args.identifier)
        except self.audit_refusal() as exc:
            code=self.audit_code(exc)
            Audit(self).append('check_merge', result=code)
            raise
        Audit(self).append('check_merge', branch=v['branch'])
        print('OK')


def add_commands(commands, enforced=False):
    for name in ('history','check-merge','list-agents','audit'):
        parser=commands.add_parser(name)
        if enforced: parser.add_argument('project')
        if name=='history':
            parser.add_argument('--since')
            parser.add_argument('--branch')
            parser.add_argument('--json',action='store_true')
        elif name=='check-merge': parser.add_argument('identifier')
        elif name=='list-agents': parser.add_argument('--json',action='store_true')
        else:
            subs=parser.add_subparsers(dest='audit_command',required=True)
            verify=subs.add_parser('verify')
            expected=verify.add_mutually_exclusive_group()
            expected.add_argument('--expect-head')
            expected.add_argument('--expect-seq',type=int)
            reseal=subs.add_parser('reseal')
            reseal.add_argument('--reason',required=True)


def invoke(gates, args):
    mutating=args.command in ('verify','accept','merge')
    audit=Audit(gates)
    if mutating:
        audit.recover()
        pending=getattr(gates,'recover_pending',None)
        if pending: pending()
        audit.recover()
    try:
        getattr(gates,args.command.replace('-','_'))(args)
    except Broken as exc:
        gates.audit_deny('AUDIT_BROKEN', str(exc))
    except gates.audit_refusal() as exc:
        if mutating and gates.audit_code(exc) not in ('AUDIT_BROKEN','AUDIT_UNAVAILABLE'):
            audit.append('deny',branch=getattr(args,'branch','') or '',result=gates.audit_code(exc))
        raise


obs = SimpleNamespace(Audit=Audit, Observability=Observability, add_commands=add_commands, invoke=invoke)


class Gates(obs.Observability):
    def __init__(self, cfg):
        self.cfg = cfg
        self.repo, self.directory = cfg["repo"], cfg["receipts"]
    @contextlib.contextmanager
    def lock(self, read_only=False):
        # Read paths never create a state directory or a lock inode.
        lock_path = self.directory.parent / "lock"
        if read_only and not lock_path.exists():
            yield
            return
        if not read_only:
            self.directory.mkdir(parents=True, exist_ok=True)
        with lock_path.open("r" if read_only else "a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def audit_deny(self, code, text):
        raise Deny(code, text)

    def audit_refusal(self):
        return Deny

    def audit_code(self, exc):
        return exc.code

    def audit_owner(self):
        # Cooperative identity is self-declared, as documented since v0.2.
        return None

    def audit_main(self):
        return self.cfg["MAIN_BRANCH"]

    def audit_git(self, *args):
        return git(self.repo, *args)

    def audit_paths(self):
        paths = {}
        for block in git(self.repo, "worktree", "list", "--porcelain").split("\n\n"):
            items = dict(line.split(" ", 1) for line in block.splitlines() if " " in line)
            if "branch" in items:
                paths[items["branch"].removeprefix("refs/heads/")] = items["worktree"]
        return paths

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
        if "audit_seq" not in record:
            obs.Audit(self).prepare(record)
        record["id"] = receipt_id(record)
        path = self.directory / (record["kind"] + "-" + record["id"] + ".json")
        # Exclusive creation prevents overwriting evidence.
        with path.open("xb") as stream:
            stream.write(canonical(record))
            stream.flush()
            os.fsync(stream.fileno())
        obs.Audit(self).receipt_event(record)
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
                                 "head_sha", "merge_tree", "test_cmd", "verdict", "result", "baseline"),
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

    def test_command(self, verification):
        if verification["test_cmd"] != self.cfg["TEST_CMD"]:
            raise Deny("TEST_CMD_MISMATCH", "verification test command differs from main config")

    def policy_files(self, base, head):
        changed = git(self.repo, "diff", "--name-only", "--no-renames", "-z",
                      base + "..." + head).split("\0")
        fixed = {"GIT_POLICY.md", "GIT_POLICY.agent-gates.md", "VERIFIER.md",
                 "VERIFIER.agent-gates.md"}
        patterns = self.cfg.get("POLICY_PATHS", "").split()
        return sorted(path for path in changed if path and (
            path.startswith(".agent-gates/") or path in fixed or
            any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)))

    def policy_change_gate(self, verification, allowed=False):
        # Trusted main config and bound refs define policy, not legacy receipt metadata.
        policy_files = self.policy_files(verification["base_sha"], verification["head_sha"])
        if self.cfg["POLICY_CHANGES"] == "deny" and policy_files and allowed is not True:
            raise Deny("POLICY_CHANGE_REQUIRES_OVERRIDE", "accept requires --allow-policy-change")
        return policy_files

    def test(self, commit):
        with tempfile.TemporaryDirectory(prefix="agent-gates-test-") as temp:
            worktree = Path(temp) / "checkout"
            git(self.repo, "worktree", "add", "--detach", str(worktree), commit)
            try:
                started = time.monotonic()
                timed_out = False
                # A file avoids waiting forever on inherited pipes held by children.
                with tempfile.TemporaryFile() as log:
                    process = subprocess.Popen(self.cfg["TEST_CMD"], shell=True,
                                               executable="/bin/bash", cwd=worktree,
                                               stdout=log, stderr=subprocess.STDOUT,
                                               start_new_session=True)
                    try:
                        process.wait(timeout=self.cfg["TEST_TIMEOUT_SECONDS"])
                    except subprocess.TimeoutExpired:
                        timed_out = True
                    finally:
                        # Own process group only; also clean up background test children.
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
                    log.seek(0)
                    output = log.read()
                lines = [line for line in output.decode(errors="replace").splitlines() if line.strip()]
                result = {"exit": 124 if timed_out else process.returncode, "timed_out": timed_out, "summary": lines[-1] if lines else "",
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
        changed = git(self.repo, "diff", "--name-only", "--no-renames", "-z", base + "..." + head).split("\0")
        policy_files = self.policy_files(base, head)
        test_files = sorted(path for path in changed if path and (
            path.startswith("tests/") or any(part == "tests" for part in Path(path).parts) or
            fnmatch.fnmatchcase(Path(path).name, "test_*") or
            fnmatch.fnmatchcase(Path(path).name, "*_test.*") or
            Path(path).name in {"conftest.py", "pytest.ini", "pyproject.toml", "setup.cfg",
                                "tox.ini", "package.json", ".gitattributes"}))
        risk_changed = git(self.repo, "diff", "--name-only", "--no-renames", "-z",
                           base + "..." + head).split("\0")
        numstat = git(self.repo, "diff", "--numstat", "--no-renames", "-z", base + "..." + head)
        changed_lines = 0
        for entry in numstat.split("\0"):
            fields = entry.split("\t", 2)
            if len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit():
                changed_lines += int(fields[0]) + int(fields[1])
        risk = []
        if changed_lines > 1000:
            risk.append("LARGE_DIFF")
        if any(Path(path).name.endswith(".lock") or Path(path).name in
               {"package-lock.json", "poetry.lock", "Cargo.lock", "go.sum"}
               for path in risk_changed if path):
            risk.append("LOCKFILE")
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
            "test_cmd": self.cfg["TEST_CMD"], "policy_files_changed": policy_files,
            "test_files_changed": test_files, "risk": risk,
            "result": result, "baseline": baseline,
            "verdict": "ACCEPT" if result["exit"] == 0 and not baseline.get("timed_out") else "REJECT",
            "created_at": stamp(), "tool_version": VERSION,
        }
        obs.Audit(self).prepare(record)
        record["id"] = receipt_id(record)
        (self.directory / (record["id"] + ".log")).write_bytes(output)
        if baseline_output is not None:
            (self.directory / (record["id"] + ".baseline.log")).write_bytes(baseline_output)
        self.write(record)
        if policy_files:
            print("WARNING: branch changes gate policy: " + ", ".join(policy_files), file=sys.stderr)
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
        obs.Audit(self).require_valid(verification)
        self.verdict(verification)
        self.test_command(verification)
        self.fresh(verification)
        policy_files = self.policy_change_gate(verification, args.allow_policy_change)
        print("author: " + verification["author"] + "; verifier: " + verification["verifier"])
        print(git(self.repo, "log", "--oneline", verification["base_sha"] + ".." + verification["head_sha"]))
        print(git(self.repo, "diff", "--stat", verification["base_sha"], verification["head_sha"]))
        print("test_cmd: " + verification["test_cmd"] + "; tests: " + verification["result"]["summary"])
        print("baseline: " + verification["baseline"].get("summary", "SKIPPED"))
        if policy_files:
            print("WARNING: branch changes gate policy: " + ", ".join(policy_files))
        if verification.get("test_files_changed"):
            print("WARNING: branch changes tests: " + ", ".join(verification["test_files_changed"]))
        if verification.get("risk"):
            print("HIGH_RISK: " + ", ".join(verification["risk"]))
        if not args.yes and input("Accept this verification? Type yes: ").strip() != "yes":
            raise EnvironmentError_("acceptance not confirmed")
        # Owner may take time at the prompt; bind to current refs again before writing.
        self.fresh(verification)
        record = {"kind": "acceptance", "schema": 1,
                  "verification_id": verification["id"], "verification_sha256": digest(raw),
                  "owner": self.cfg["OWNER_NAME"], "created_at": stamp(),
                  "expires_at": (datetime.now(timezone.utc) +
                                 timedelta(hours=self.cfg["ACCEPT_TTL_HOURS"])).isoformat().replace("+00:00", "Z"),
                  "signature": None, "allow_policy_change": args.allow_policy_change}
        obs.Audit(self).prepare(record)
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
        obs.Audit(self).require_valid(acceptance)
        self.signature(acceptance)
        try:
            expired = clock(acceptance["expires_at"]) <= datetime.now(timezone.utc)
        except (ValueError, TypeError, AttributeError):
            raise Deny("RECEIPT_TAMPERED", "invalid acceptance expiry")
        if expired:
            raise Deny("ACCEPTANCE_EXPIRED", "acceptance TTL has elapsed")
        verification, raw = self.load("verification", acceptance["verification_id"])
        obs.Audit(self).require_valid(verification)
        if digest(raw) != acceptance["verification_sha256"]:
            raise Deny("RECEIPT_TAMPERED", "accepted verification bytes changed")
        self.verdict(verification)
        self.test_command(verification)
        self.policy_change_gate(verification, acceptance.get("allow_policy_change", False))
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
        bundle = canonical({"verification": verification, "acceptance": acceptance, "merge": record})
        blob = run(["git", "-C", str(self.repo), "hash-object", "-w", "--stdin"], data=bundle)
        if blob.returncode:
            raise EnvironmentError_("could not store receipt note")
        git(self.repo, "notes", "--ref=refs/notes/agent-gates", "add", "-C", blob.stdout.decode().strip(), commit)
        print(record["id"])

    def status(self, args):
        if args.all:
            return self.status_all(args)
        if args.notify:
            self.audit_owner()
            raise Deny("INVALID_ARGUMENT", "--notify requires --all")
        self.audit_report_break()
        for path in sorted(self.directory.glob("verification-*.json")):
            identifier = path.stem.removeprefix("verification-")
            try:
                verification, _ = self.load("verification", identifier)
                if args.branch and verification["branch"] != args.branch:
                    continue
                obs.Audit(self).require_valid(verification)
                self.verdict(verification)
                self.test_command(verification)
                self.fresh(verification)
                state = "VALID"
            except Deny as exc:
                state = "INVALIDATED" if exc.code == "RECEIPT_INVALIDATED" else exc.code
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
                state = "INVALIDATED" if exc.code == "RECEIPT_INVALIDATED" else exc.code
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
    if sys.argv[1:3] == ["github", "protect"]:
        spec = importlib.util.spec_from_file_location("github_protect", Path(__file__).resolve().parent / "github_protect.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.main(sys.argv[3:])
    if sys.argv[1:3] == ["publish", "attest"]:
        parser = argparse.ArgumentParser()
        parser.add_argument("old")
        parser.add_argument("new")
        parser.add_argument("--key", required=True)
        parser.add_argument("--repository", default="HlinorAI/hlinor-agent-gates")
        args = parser.parse_args(sys.argv[3:])
        spec = importlib.util.spec_from_file_location("github_verify", Path(__file__).resolve().parent / "github_verify.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        try:
            record = module.attest(Path.cwd(), args.old, args.new, args.key, args.repository)
            print("\n".join(record["commits"]))
            return 0
        except (module.Invalid, OSError, ValueError) as exc:
            print("DENY PUBLISH_ATTESTATION_FAILED: " + " ".join(str(exc).splitlines()))
            return 1
    # Protected installed entry point never falls back to cooperative repository code.
    installed = Path(__file__).resolve().parent == Path("/opt/agent-gates/bin")
    if installed or (len(sys.argv) > 1 and sys.argv[1] in ("enforce", "doctor")):
        source = Path(__file__).resolve().parent
        # Validate before importing project-controlled Python into a root process.
        if sys.argv[1:3] in (["enforce", "init"], ["enforce", "upgrade"]):
            paths = [source / name for name in
                     ("agent-gates", "agent_gates.py", "enforced.py", "gate-receive-pack", "pre-receive", "ag-run", "enforced_runtime.py", "github_verify.py", "github_protect.py")]
            paths += [source, *source.parents]
            trusted = (source.name == "bin" and ".agent-gates" not in source.parts
                       and ".agent-gates" not in Path(__file__).absolute().parts
                       and (source.parent / ".git").exists()
                       and (source.parent / "docs/spec/v0.4-enforced.md").is_file())
            try:
                trusted = trusted and all(not path.is_symlink() and path.lstat().st_uid == 0
                                          and not path.lstat().st_mode & 0o022
                                          and (stat.S_ISREG(path.lstat().st_mode) or
                                               stat.S_ISDIR(path.lstat().st_mode)) for path in paths)
            except OSError:
                trusted = False
            if not trusted:
                print("DENY UNTRUSTED_SOURCE: enforce init requires a protected root-owned kit checkout", file=sys.stderr)
                return 1
        module_spec = importlib.util.spec_from_file_location("enforced", source / "enforced.py")
        enforced = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(enforced)
        return enforced.main(sys.argv[1:])
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("branch")
    verify.add_argument("--as", dest="verifier", required=True)
    verify.add_argument("--no-baseline", action="store_true")
    accept = commands.add_parser("accept")
    accept.add_argument("identifier")
    accept.add_argument("--yes", action="store_true")
    accept.add_argument("--allow-policy-change", action="store_true")
    merge = commands.add_parser("merge")
    merge.add_argument("identifier")
    status = commands.add_parser("status")
    status.add_argument("branch", nargs="?")
    status.add_argument("--all", action="store_true")
    status.add_argument("--json", action="store_true")
    status.add_argument("--notify", action="store_true")
    obs.add_commands(commands)
    args = parser.parse_args()
    if args.command in ("verify", "status") and (
            getattr(args, "branch", None) is not None and
            not re.fullmatch(r"agent/[a-z0-9-]+", args.branch)):
        parser.error("branch must match agent/<name>")
    try:
        git_version()
        gates = Gates(config())
        read_only = args.command in ("history", "list-agents") or (
            args.command == "status" and not args.notify) or (
            args.command == "audit" and args.audit_command == "verify")
        with gates.lock(read_only=read_only):
            obs.invoke(gates, args)
        return 0
    except Deny as exc:
        print("DENY " + exc.code + ": " + " ".join(exc.text.splitlines()))
        return 1
    except (EnvironmentError_, OSError, ValueError, KeyError, TypeError, EOFError) as exc:
        print("ERROR: " + " ".join(str(exc).splitlines()), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/python3
"""Protected notifier supervisor; stdin is supplied by the trusted gate, never test code."""
import fcntl
import json
import os
from pathlib import Path
import pwd
import shlex
import signal
import subprocess
import sys
import tempfile


def main():
    account=pwd.getpwnam('ag-notify')
    if os.getuid()!=account.pw_uid or os.environ.get('SUDO_USER') not in ('agent-gates','root'):
        return 1
    request=json.load(sys.stdin)
    if request.get('cleanup') is True:
        os.execv('/usr/bin/pkill',['pkill','-KILL','-u',str(account.pw_uid)])
    with Path('/etc/agent-gates/notify.lock').open('r+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        try:
            command=request['command'];message=request['message']
            env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C.UTF-8'}
            for line in Path('/etc/agent-gates/notify.env').read_text().splitlines():
                if not line.strip() or line.lstrip().startswith('#'):continue
                key,sep,value=line.partition('=');parts=shlex.split(value,comments=True)
                if not sep or not key.replace('_','a').isalnum() or len(parts)!=1:raise ValueError('invalid notify.env')
                env[key]=parts[0]
            with tempfile.TemporaryFile() as output:
                process=subprocess.Popen(command,shell=True,env=env,stdin=subprocess.PIPE,
                                         stdout=output,stderr=output,start_new_session=True,cwd='/')
                try:
                    process.communicate(json.dumps(message).encode()+b'\n',timeout=10)
                    ok=process.returncode==0
                except subprocess.TimeoutExpired:ok=False
                finally:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    process.wait()
        except (ValueError,KeyError,OSError,subprocess.SubprocessError):ok=False
        # Child output never enters this trusted result channel. Kill the complete UID,
        # including detached children and this supervisor; sudo waits until it is gone.
        print(json.dumps({'ok':ok}),flush=True)
        os.execv('/usr/bin/pkill',['pkill','-KILL','-u',str(account.pw_uid)])


if __name__=='__main__':sys.exit(main())

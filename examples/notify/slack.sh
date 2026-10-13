#!/usr/bin/env bash
# Optional Owner-installed hook. Never put the webhook URL in repository policy.
set -euo pipefail
exec /usr/bin/python3 -I -c '
import json,os,sys,urllib.request
message=json.load(sys.stdin)
request=urllib.request.Request(os.environ["SLACK_WEBHOOK_URL"],
    data=json.dumps({"text":message["text"]}).encode(),headers={"Content-Type":"application/json"})
with urllib.request.urlopen(request,timeout=8) as response:
    if response.read().strip()!=b"ok":sys.exit(1)
'

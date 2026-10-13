#!/usr/bin/env bash
# Optional Owner-installed hook. Secrets come from the notifier environment.
set -euo pipefail
exec /usr/bin/python3 -I -c '
import json,os,sys,urllib.request
message=json.load(sys.stdin)
body=json.dumps({"chat_id":os.environ["TELEGRAM_CHAT_ID"],"text":message["text"]}).encode()
url="https://api.telegram.org/bot"+os.environ["TELEGRAM_BOT_TOKEN"]+"/sendMessage"
request=urllib.request.Request(url,data=body,headers={"Content-Type":"application/json"})
with urllib.request.urlopen(request,timeout=8) as response:
    if not json.load(response).get("ok"):sys.exit(1)
'

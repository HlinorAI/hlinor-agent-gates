#!/usr/bin/env bash
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd -P)"
if command -v docker >/dev/null 2>&1; then RUNTIME=docker
elif command -v podman >/dev/null 2>&1; then RUNTIME=podman
else echo 'STOP: disposable container required; never provision host'; exit 2; fi
"$RUNTIME" build -f "$KIT/tests/containers/enforced.Dockerfile" -t agent-gates-mcp-tests:0.7.0 "$KIT/tests/containers"
"$RUNTIME" run --rm --init --hostname gates-tests --add-host gates-tests:127.0.0.1 --network=none \
  --mount "type=bind,src=$KIT,dst=/kit,readonly" agent-gates-mcp-tests:0.7.0 \
  bash -c 'bash /kit/tests/containers/phase_a.sh && /usr/bin/python3 -IB /kit/tests/containers/mcp_enforced.py'

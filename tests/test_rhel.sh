#!/usr/bin/env bash
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd -P)"
if command -v docker >/dev/null 2>&1; then RUNTIME=docker
elif command -v podman >/dev/null 2>&1; then RUNTIME=podman
else echo 'STOP: docker or podman required; never provision host'; exit 2; fi
"$RUNTIME" build -f "$KIT/tests/containers/rhel.Dockerfile" -t agent-gates-rhel-tests:0.6.0 "$KIT/tests/containers"
"$RUNTIME" run --rm --init --hostname gates-tests --add-host gates-tests:127.0.0.1 --network=none \
  --mount "type=bind,src=$KIT,dst=/kit,readonly" agent-gates-rhel-tests:0.6.0 bash /kit/tests/containers/rhel.sh

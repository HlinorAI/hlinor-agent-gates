#!/usr/bin/env bash
# Never provision accounts or scheduler policies on the machine running this script.
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd -P)"
if command -v docker >/dev/null 2>&1; then RUNTIME=docker
elif command -v podman >/dev/null 2>&1; then RUNTIME=podman
else echo 'STOP: docker or podman required; enforced tests cannot run on the host' >&2; exit 2
fi
"$RUNTIME" info >/dev/null
IMAGE=agent-gates-enforced-tests:0.4.0
"$RUNTIME" build -f "$KIT/tests/containers/enforced.Dockerfile" -t "$IMAGE" "$KIT/tests/containers"
"$RUNTIME" run --rm --init --hostname gates-tests --add-host gates-tests:127.0.0.1 --network=none \
  --mount "type=bind,src=$KIT,dst=/kit,readonly" "$IMAGE" bash /kit/tests/containers/enforced.sh

#!/usr/bin/env bash
# Separate v0.5 integration: existing enforced release tests remain unchanged.
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd -P)"
if command -v docker >/dev/null 2>&1; then RUNTIME=docker
elif command -v podman >/dev/null 2>&1; then RUNTIME=podman
else echo 'STOP: disposable container runtime required' >&2; exit 2
fi
"$RUNTIME" info >/dev/null
IMAGE=agent-gates-github-tests:0.5.0
"$RUNTIME" build -f "$KIT/tests/containers/enforced.Dockerfile" -t "$IMAGE" "$KIT/tests/containers"
"$RUNTIME" run --rm --init --hostname gates-tests --add-host gates-tests:127.0.0.1 --network=none \
  --mount "type=bind,src=$KIT,dst=/kit,readonly" "$IMAGE" \
  bash -c 'bash /kit/tests/containers/phase_b.sh && python3 -IB /kit/tests/containers/github_notes.py'

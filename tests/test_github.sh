#!/usr/bin/env bash
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd -P)"
exec python3 -IB "$KIT/tests/test_github.py"

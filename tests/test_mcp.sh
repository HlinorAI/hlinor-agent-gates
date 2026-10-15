#!/usr/bin/env bash
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd -P)"
exec /usr/bin/python3 -IB "$KIT/tests/test_mcp.py"

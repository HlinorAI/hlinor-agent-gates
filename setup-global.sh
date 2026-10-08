#!/usr/bin/env bash
# Configure automatic installation; use --dry-run to preview machine changes.
set -euo pipefail
KIT="$(cd "$(dirname "$0")" && pwd -P)"
export PYTHONDONTWRITEBYTECODE=1
exec python3 "$KIT/scripts/setup_global.py" "$@"

#!/usr/bin/env bash
# Create and verify a git bundle backup. Part of hlinor-agent-gates.
set -euo pipefail
repo="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
# shellcheck disable=SC1091
source "$repo/.agent-gates.conf"
mkdir -p "$BACKUP_DIR"
out="$BACKUP_DIR/$(basename "$repo")-$(date +%F-%H%M).bundle"
git -C "$repo" bundle create "$out" --all 2>/dev/null
git bundle verify "$out" >/dev/null 2>&1 && echo "BUNDLE_OK $out ($(du -h "$out" | cut -f1))" || { echo "BUNDLE_FAIL $out"; exit 1; }
echo "Copy it off this machine, e.g.: scp <host>:$out ."

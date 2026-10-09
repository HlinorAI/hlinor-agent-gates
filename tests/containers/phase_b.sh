#!/usr/bin/env bash
set -euo pipefail
[ -f /.dockerenv ] || [ -f /run/.containerenv ] || { echo 'STOP: disposable container required'; exit 2; }
[ "$(id -u)" = 0 ] || exit 2
bash /kit/tests/containers/phase_a.sh > /tmp/phase-a.log 2>&1 || { cat /tmp/phase-a.log; exit 1; }
tail -1 /tmp/phase-a.log
/usr/bin/python3 -I /kit/tests/containers/phase_b.py

#!/usr/bin/env bash
set -euo pipefail
[ -f /.dockerenv ] || [ -f /run/.containerenv ] || { echo 'STOP: disposable container required'; exit 2; }
[ "$(id -u)" = 0 ] || exit 2
bash /kit/tests/containers/phase_b.sh
/usr/bin/python3 -I /kit/tests/containers/enforced_attacks.py

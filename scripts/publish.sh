#!/usr/bin/env bash
# Owner-only publication. Never invoked by agents or by the test suites against GitHub.
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd -P)"
SOURCE=""; KEY=""; AUDIT_EXPORT=""; REPO=HlinorAI/hlinor-agent-gates
while [ "$#" -gt 0 ]; do
  case "$1" in
    --audit-export) AUDIT_EXPORT="$2"; shift 2;;
    --source) SOURCE="$2"; shift 2;;
    --key) KEY="$2"; shift 2;;
    --repository) REPO="$2"; shift 2;;
    *) echo 'Usage: scripts/publish.sh --source <server-repository> --key <Mac-key> [--repository owner/repo] [--audit-export file.tar.gz]' >&2; exit 2;;
  esac
done
[ -n "$SOURCE" ] && [ -n "$KEY" ] || { echo 'DENY PUBLISH_INPUT_MISSING: source and Owner Mac key required'; exit 1; }
[ "$(git branch --show-current)" = main ] || { echo 'DENY NOT_MAIN: publish from the Owner main checkout'; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo 'DENY MAIN_DIRTY: Owner checkout must be clean'; exit 1; }
git remote get-url origin >/dev/null
# Fetch the gate's exact branch and notes; the source is an explicit argument, no remote is created.
git fetch "$SOURCE" refs/heads/main
SOURCE_HEAD="$(git rev-parse FETCH_HEAD)"
git merge --ff-only "$SOURCE_HEAD"
# Never silently discard receipts. A missing notes ref is allowed only if the range has no gate merges.
NOTE_RC=0
git ls-remote --exit-code "$SOURCE" refs/notes/agent-gates >/dev/null || NOTE_RC=$?
if [ "$NOTE_RC" = 0 ]; then
  git fetch "$SOURCE" refs/notes/agent-gates:refs/notes/agent-gates
elif [ "$NOTE_RC" != 2 ]; then
  exit "$NOTE_RC"
fi
git fetch origin refs/heads/main
OLD="$(git rev-parse FETCH_HEAD)"
NEW="$(git rev-parse refs/heads/main)"
git merge-base --is-ancestor "$OLD" "$NEW" || { echo 'DENY NON_FAST_FORWARD: GitHub main is not an ancestor'; exit 1; }
[ "$OLD" != "$NEW" ] || { echo 'Nothing to publish.'; exit 0; }
# Preserve earlier published attestations before adding the new one.
NOTE_RC=0
git ls-remote --exit-code origin refs/notes/agent-gates-publish >/dev/null || NOTE_RC=$?
if [ "$NOTE_RC" = 0 ]; then
  git fetch origin refs/notes/agent-gates-publish:refs/notes/agent-gates-publish
elif [ "$NOTE_RC" != 2 ]; then
  exit "$NOTE_RC"
fi
while IFS= read -r COMMIT; do
  MESSAGE="$(git show -s --format=%B "$COMMIT")"
  case "$MESSAGE" in
    "agent-gates merge"*)
      git notes --ref=refs/notes/agent-gates show "$COMMIT" >/dev/null || {
        echo "DENY RECEIPT_NOTE_MISSING: gate merge $COMMIT has no receipt note"; exit 1;
      };;
  esac
done < <(git rev-list --first-parent --reverse "$OLD..$NEW")
printf 'Publish first-parent commits:\n'
git log --first-parent --reverse --format='%h %s' "$OLD..$NEW"
printf 'Sign and publish this exact range? Type y: '
read -r ANSWER
[ "$ANSWER" = y ] || { echo 'DENY PUBLISH_NOT_CONFIRMED: publication cancelled'; exit 1; }
if [ -n "$AUDIT_EXPORT" ]; then set -- --audit-export "$AUDIT_EXPORT"; else set --; fi
"$KIT/bin/agent-gates" publish attest "$OLD" "$NEW" --key "$KEY" --repository "$REPO" "$@"
[ "$(git rev-parse refs/heads/main)" = "$NEW" ] || { echo 'DENY MAIN_MOVED: main changed while confirming'; exit 1; }
REFS=("$NEW:refs/heads/main" refs/notes/agent-gates-publish)
if git show-ref --verify --quiet refs/notes/agent-gates; then
  REFS+=(refs/notes/agent-gates)
fi
# Bind the reviewed GitHub base against concurrent publication, and update all refs together.
git push --atomic --force-with-lease="refs/heads/main:$OLD" origin "${REFS[@]}"

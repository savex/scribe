#!/usr/bin/env bash
# Every test must sit in exactly one tag module: smoke::, functional::, integration:: or scenario::
# (workfiles/test-list.md, section 2). Doc examples are not tests and are skipped.
#   scripts/check-test-tags.sh           check, print counts per tag
set -euo pipefail
cd "$(dirname "$0")/.."

list=$(cargo test --workspace --all-features --locked -q -- --list --format terse 2>/dev/null |
  sed -n 's/: test$//p' | grep -v ' - (line ' || true)
[ -n "$list" ] || { echo "check-test-tags: no tests listed" >&2; exit 1; }

bad=0
smoke=0 functional=0 integration=0 scenario=0
while IFS= read -r name; do
  tags=$(tr ':' '\n' <<<"$name" | grep -cxE 'smoke|functional|integration|scenario' || true)
  if [ "$tags" -ne 1 ]; then
    echo "check-test-tags: '$name' has $tags tag modules, expected exactly 1" >&2
    bad=1
    continue
  fi
  tag=$(tr ':' '\n' <<<"$name" | grep -xE 'smoke|functional|integration|scenario')
  eval "$tag=\$(( $tag + 1 ))"
done <<<"$list"

for t in smoke functional integration scenario; do
  eval "n=\$$t"
  printf '%-12s %s\n' "$t" "$n"
done
exit $bad

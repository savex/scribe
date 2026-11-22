#!/usr/bin/env bash
# Every test has exactly one tag: smoke, functional, integration or scenario (workfiles/test-list.md).
#   - Tests in a test binary named after a tag take that tag: tests/smoke, tests/integration,
#     tests/scenario (crate scribe-tests) and crates/<crate>/tests/functional. Their own paths must not
#     contain another tag module.
#   - Tests inside source files (unit tests that need private code) sit in exactly one tag module,
#     e.g. `units::tests::functional::parses_sizes`.
# Prints the count per tag. Needs cargo-nextest and python3. Doc examples are not listed.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo nextest list --workspace --all-features --locked --message-format json 2>/dev/null | python3 -c '
import json, sys
TAGS = ("smoke", "functional", "integration", "scenario")
suites = json.load(sys.stdin)["rust-suites"]
count = dict.fromkeys(TAGS, 0)
bad = []
for binary_id, suite in suites.items():
    binary = suite["binary-name"]
    for name in suite["testcases"]:
        in_path = [s for s in name.split("::")[:-1] if s in TAGS]
        if binary in TAGS:
            if in_path:
                bad.append(f"{binary_id} {name}: tag module {in_path} inside the {binary} binary")
                continue
            count[binary] += 1
        elif len(in_path) != 1:
            bad.append(f"{binary_id} {name}: {len(in_path)} tag modules, expected exactly 1")
        else:
            count[in_path[0]] += 1
for line in bad:
    print("check-test-tags:", line, file=sys.stderr)
for tag in TAGS:
    print(f"{tag:<12} {count[tag]}")
sys.exit(1 if bad else 0)
'

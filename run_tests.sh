#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

usage() {
    echo "Usage: $0 [options]"
    echo "  -c, --config <debug|release>   Build configuration (default: release)"
    echo "  -f, --filter <substring>       Run only tests matching the substring"
    echo "  -l, --list                     List available tests without running"
    echo "  -h, --help                     Show this help"
}

CONFIG="release"
FILTER=""
LIST=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--config)
            CONFIG="${2:?missing value for $1}"
            shift 2
            ;;
        -f|--filter)
            FILTER="${2:?missing value for $1}"
            shift 2
            ;;
        -l|--list)
            LIST=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [[ "$LIST" -eq 1 ]]; then
    swift test list
    exit 0
fi

# Run the test bundle directly with xcrun xctest instead of `swift test`:
# SwiftPM pipes the xctest process stdout and drops buffered chunks, which
# truncates the tests' printed output. xcrun xctest inherits stdout directly
# and streams everything.
# -enable-testing is required so tests can `@testable import Argon2`
# (swift test does this implicitly; swift build does not).
swift build -c "$CONFIG" --build-tests -Xswiftc -enable-testing

BUNDLE="$(ls -d .build/"$CONFIG"/*.xctest 2>/dev/null | head -1)"
if [[ -z "$BUNDLE" ]]; then
    echo "Test bundle not found under .build/$CONFIG" >&2
    exit 1
fi

ARGS=()
if [[ -n "$FILTER" ]]; then
    SELECTORS="$(swift test list | grep -E "$FILTER" | paste -sd, - || true)"
    if [[ -z "$SELECTORS" ]]; then
        echo "No tests match filter: $FILTER" >&2
        exit 1
    fi
    ARGS+=(-XCTest "$SELECTORS")
fi

echo "Running tests (config: $CONFIG${FILTER:+, filter: $FILTER}) via xcrun xctest..."
START=$(date +%s)
xcrun xctest "${ARGS[@]+"${ARGS[@]}"}" "$BUNDLE"
ELAPSED=$(( $(date +%s) - START ))
echo "Tests passed in ${ELAPSED}s."
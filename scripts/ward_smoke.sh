#!/usr/bin/env bash
# ward_smoke.sh — smoke-test a ward binary for the run-wrapper unwrap fix.
#
# Proves two things by piping PreToolUse hook events through `ward eval -v`:
#   1. `uv run python -c "..."` now parses to name=python, so the no-python-c
#      rule matches (DENY) — the run-wrapper evasion is closed.
#   2. A benign command (`ls`) is still allowed (no deny output).
#
# Usage: scripts/ward_smoke.sh [path-to-ward-binary]
#   Defaults to the live hook binary at C:/Users/Q/go/bin/ward.exe.
#
# The script wires a throwaway rules dir containing only no-python-c.yaml so the
# result does not depend on which profiles happen to be installed, and it uses a
# throwaway session id whose state file is deleted at the end.
set -euo pipefail

WARD_BIN="${1:-C:/Users/Q/go/bin/ward.exe}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION="ward-smoke-$$"
CWD="$REPO_ROOT"

# Isolated rules dir: only no-python-c so we test exactly the rule the fix targets.
RULES_DIR="$(mktemp -d)"
cp "$REPO_ROOT/builtin_profiles/python/rules/no-python-c.yaml" "$RULES_DIR/no-python-c.yaml"
export WARD_RULES_PATH="$RULES_DIR"

STATE_DIR="${TEMP:-/tmp}/ward"
cleanup() {
  rm -rf "$RULES_DIR"
  rm -f "$STATE_DIR/$SESSION.json"
}
trap cleanup EXIT

emit_event() {
  # $1 = command string (already JSON-escaped by the caller)
  printf '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"%s"},"session_id":"%s","cwd":"%s"}' \
    "$1" "$SESSION" "$CWD"
}

echo "=== ward binary: $WARD_BIN ==="
echo

echo "--- CASE 1: uv run python -c (expect DENY + parsed name=python) ---"
set +e
emit_event 'uv run python -c \"print(1)\"' | "$WARD_BIN" eval -v
echo "(exit=$?)"
set -e
echo

echo "--- CASE 2: ls (expect ALLOW / blank deny output) ---"
set +e
emit_event 'ls' | "$WARD_BIN" eval -v
echo "(exit=$?)"
set -e
echo

echo "=== smoke complete ==="

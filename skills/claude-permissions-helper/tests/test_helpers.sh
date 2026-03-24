#!/usr/bin/env bash
# Shared test helpers for claude-permissions-helper tests.
# Source this file, don't execute it directly.
#
# All expect_* functions accept: (name, cmd) or (name, cmd, perms, deny).
# When perms/deny are omitted, they fall back to ALL_ALLOW/ALL_DENY globals
# (set these in your test file before calling expect_*).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
HOOK="$SCRIPT_DIR/../hooks/approve-compound-bash.sh"

BASH_BIN="${BASH_BIN:-/opt/homebrew/bin/bash}"
if [[ "${BASH_VERSINFO[0]}" -lt 4 || ( "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -lt 3 ) ]]; then
  if [[ -x "$BASH_BIN" ]]; then exec "$BASH_BIN" "${BASH_SOURCE[1]}" "$@"; fi
  echo "SKIP: bash 4.3+ required"; exit 0
fi

PASS=0 FAIL=0
pass() { ((PASS++)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { ((FAIL++)); printf '  \033[31mFAIL\033[0m %s — %s\n' "$1" "$2"; }

run_hook() {
  local cmd="$1" perms="$2" deny="${3:-}"
  local input
  input=$(jq -n --arg c "$cmd" '{"tool_input":{"command":$c}}')
  local args=(--permissions "$perms")
  [[ -n "$deny" ]] && args+=(--deny "$deny")
  RESULT=$("$BASH_BIN" "$HOOK" "${args[@]}" <<< "$input" 2>/dev/null)
  return $?
}

print_results() {
  echo ""
  echo "Results: $PASS passed, $FAIL failed"
  [[ $FAIL -eq 0 ]] && exit 0 || exit 1
}

# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

expect_allow() {
  local name="$1" cmd="$2" perms="${3:-${ALL_ALLOW:-}}" deny="${4:-${ALL_DENY:-}}"
  run_hook "$cmd" "$perms" "$deny"
  local rc=$?
  if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
    pass "$name"
  else
    fail "$name" "exit=$rc output=$RESULT"
  fi
}

expect_allow_or_fallthrough() {
  local name="$1" cmd="$2" perms="${3:-${ALL_ALLOW:-}}" deny="${4:-${ALL_DENY:-}}"
  run_hook "$cmd" "$perms" "$deny"
  local rc=$?
  if [[ $rc -eq 0 ]]; then
    if jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
      pass "$name (auto-approved)"
    elif [[ -z "$RESULT" ]] || ! jq -e '.hookSpecificOutput.permissionDecision' <<< "$RESULT" &>/dev/null; then
      pass "$name (fallthrough, also OK)"
    else
      fail "$name" "exit=$rc output=$RESULT"
    fi
  else
    fail "$name" "exit=$rc output=$RESULT"
  fi
}

expect_deny() {
  local name="$1" cmd="$2" perms="${3:-${ALL_ALLOW:-}}" deny="${4:-${ALL_DENY:-}}"
  run_hook "$cmd" "$perms" "$deny"
  local rc=$?
  if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
    pass "$name"
  else
    fail "$name" "exit=$rc output=$RESULT"
  fi
}

expect_fallthrough() {
  local name="$1" cmd="$2" perms="${3:-${ALL_ALLOW:-}}" deny="${4:-${ALL_DENY:-}}"
  run_hook "$cmd" "$perms" "$deny"
  local rc=$?
  if [[ $rc -eq 0 ]] && { [[ -z "$RESULT" ]] || ! jq -e '.hookSpecificOutput.permissionDecision' <<< "$RESULT" &>/dev/null; }; then
    pass "$name"
  else
    fail "$name" "exit=$rc output=$RESULT"
  fi
}

expect_not_approved() {
  local name="$1" cmd="$2" perms="${3:-${ALL_ALLOW:-}}" deny="${4:-${ALL_DENY:-}}"
  run_hook "$cmd" "$perms" "$deny"
  local rc=$?
  if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
    fail "$name → AUTO-APPROVED" "should not be approved"
  else
    pass "$name"
  fi
}

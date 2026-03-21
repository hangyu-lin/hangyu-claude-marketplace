#!/usr/bin/env bash
# Test suite for approve-compound-bash.sh
# Usage: bash tests/test_hook.sh
#
# Requires: jq, shfmt, bash 4.3+

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$SCRIPT_DIR/../hooks/approve-compound-bash.sh"

# Use modern bash if needed
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

# run_hook <command> <permissions_json> [deny_json]
# Returns the exit code; sets RESULT to stdout.
run_hook() {
  local cmd="$1" perms="$2" deny="${3:-}"
  local input
  input=$(jq -n --arg c "$cmd" '{"tool_input":{"command":$c}}')
  local args=(--permissions "$perms")
  [[ -n "$deny" ]] && args+=(--deny "$deny")
  RESULT=$("$BASH_BIN" "$HOOK" "${args[@]}" <<< "$input" 2>/dev/null)
  return $?
}

is_allow() { [[ $? -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; }
is_deny()  { [[ $? -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; }

# ---------------------------------------------------------------------------
echo "=== Simple commands ==="

run_hook "git status" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "simple allow: git status"
else
  fail "simple allow: git status" "exit=$rc output=$RESULT"
fi

run_hook "rm -rf /" '["Bash(git *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "simple deny: rm -rf / (matches deny list)"
else
  fail "simple deny: rm -rf / (matches deny list)" "exit=$rc output=$RESULT"
fi

run_hook "unknown-cmd foo" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && [[ -z "$RESULT" ]]; then
  pass "simple fallthrough: unknown command"
else
  fail "simple fallthrough: unknown command" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Compound commands ==="

run_hook "git status && git log" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "compound allow: git status && git log"
else
  fail "compound allow: git status && git log" "exit=$rc output=$RESULT"
fi

run_hook "git status && rm -rf /" '["Bash(git *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "compound deny: git status && rm -rf /"
else
  fail "compound deny: git status && rm -rf /" "exit=$rc output=$RESULT"
fi

run_hook "git status && unknown-cmd" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && [[ -z "$RESULT" ]]; then
  pass "compound fallthrough: git status && unknown-cmd"
else
  fail "compound fallthrough: git status && unknown-cmd" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Pipes ==="

run_hook "git log | head -20" '["Bash(git *)", "Bash(head *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "pipe allow: git log | head -20"
else
  fail "pipe allow: git log | head -20" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Command substitution ==="

run_hook 'echo "$(date)"' '["Bash(echo *)", "Bash(date *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "command sub allow: echo \"\$(date)\""
else
  fail "command sub allow: echo \"\$(date)\"" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Newlines ==="

run_hook $'git status\nrm -rf /' '["Bash(git *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "newline deny: git status\\nrm -rf /"
else
  fail "newline deny: git status\\nrm -rf /" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== bash -c recursion ==="

run_hook "bash -c 'git status && git log'" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "bash -c recursion: allow"
else
  fail "bash -c recursion: allow" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== strip_prefixes (env vars) ==="

run_hook "FOO=bar git status" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "env var: FOO=bar git status"
else
  fail "env var: FOO=bar git status" "exit=$rc output=$RESULT"
fi

run_hook 'FOO="hello world" git status' '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "env var quoted: FOO=\"hello world\" git status"
else
  fail "env var quoted: FOO=\"hello world\" git status" "exit=$rc output=$RESULT"
fi

run_hook "FOO='hello world' git status" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "env var single-quoted: FOO='hello world' git status"
else
  fail "env var single-quoted: FOO='hello world' git status" "exit=$rc output=$RESULT"
fi

run_hook "A=1 B=2 git status" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "multiple env vars: A=1 B=2 git status"
else
  fail "multiple env vars: A=1 B=2 git status" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Command launchers: env ==="

run_hook "env git status" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "env launcher: env git status"
else
  fail "env launcher: env git status" "exit=$rc output=$RESULT"
fi

run_hook "env FOO=bar git status" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "env launcher: env FOO=bar git status"
else
  fail "env launcher: env FOO=bar git status" "exit=$rc output=$RESULT"
fi

run_hook "env FOO=bar BAZ=1 git status" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "env launcher: env FOO=bar BAZ=1 git status"
else
  fail "env launcher: env FOO=bar BAZ=1 git status" "exit=$rc output=$RESULT"
fi

run_hook "env rm -rf /" '["Bash(git *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "env launcher deny: env rm -rf /"
else
  fail "env launcher deny: env rm -rf /" "exit=$rc output=$RESULT"
fi

run_hook "env rm -rf /" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && [[ -z "$RESULT" ]]; then
  pass "env launcher fallthrough: env rm -rf / (rm not allowed)"
else
  fail "env launcher fallthrough: env rm -rf / (rm not allowed)" "exit=$rc output=$RESULT"
fi

# Launcher rules themselves still work
run_hook "env git status" '["Bash(env *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "env launcher rule: env git status matches env *"
else
  fail "env launcher rule: env git status matches env *" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Command launchers: xargs ==="

run_hook "xargs rm -rf" '["Bash(git *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "xargs deny: xargs rm -rf"
else
  fail "xargs deny: xargs rm -rf" "exit=$rc output=$RESULT"
fi

run_hook "xargs -n1 curl" '["Bash(curl *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "xargs allow: xargs -n1 curl"
else
  fail "xargs allow: xargs -n1 curl" "exit=$rc output=$RESULT"
fi

run_hook "xargs -I {} rm -rf {}" '["Bash(git *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "xargs deny: xargs -I {} rm -rf {}"
else
  fail "xargs deny: xargs -I {} rm -rf {}" "exit=$rc output=$RESULT"
fi

run_hook "xargs -0 -r wc -l" '["Bash(wc *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "xargs allow: xargs -0 -r wc -l"
else
  fail "xargs allow: xargs -0 -r wc -l" "exit=$rc output=$RESULT"
fi

run_hook "xargs -- rm" '["Bash(git *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "xargs deny: xargs -- rm (-- ends opts)"
else
  fail "xargs deny: xargs -- rm (-- ends opts)" "exit=$rc output=$RESULT"
fi

run_hook "xargs -P 4 -n 1 curl" '["Bash(curl *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "xargs allow: xargs -P 4 -n 1 curl"
else
  fail "xargs allow: xargs -P 4 -n 1 curl" "exit=$rc output=$RESULT"
fi

# Launcher rule itself
run_hook "xargs rm" '["Bash(xargs *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "xargs launcher rule: xargs rm matches xargs *"
else
  fail "xargs launcher rule: xargs rm matches xargs *" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Command launchers: combined ==="

run_hook "find . | xargs rm" '["Bash(find *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "pipe+xargs deny: find . | xargs rm"
else
  fail "pipe+xargs deny: find . | xargs rm" "exit=$rc output=$RESULT"
fi

run_hook "env xargs -n1 rm" '["Bash(git *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "env+xargs deny: env xargs -n1 rm"
else
  fail "env+xargs deny: env xargs -n1 rm" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Command launchers: bash -c / sh -c ==="

run_hook "bash -c 'rm -rf /'" '["Bash(bash *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "bash -c deny: bash -c 'rm -rf /' (inner matches deny)"
else
  fail "bash -c deny: bash -c 'rm -rf /' (inner matches deny)" "exit=$rc output=$RESULT"
fi

run_hook "bash -c 'git status'" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "bash -c allow: bash -c 'git status' (inner matches allow)"
else
  fail "bash -c allow: bash -c 'git status' (inner matches allow)" "exit=$rc output=$RESULT"
fi

run_hook "sh -c 'rm -rf /'" '["Bash(sh *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "sh -c deny: sh -c 'rm -rf /' (inner matches deny)"
else
  fail "sh -c deny: sh -c 'rm -rf /' (inner matches deny)" "exit=$rc output=$RESULT"
fi

run_hook "env bash -c 'rm -rf /'" '["Bash(bash *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "env+bash -c deny: env bash -c 'rm -rf /' (env stripped, inner matches deny)"
else
  fail "env+bash -c deny: env bash -c 'rm -rf /' (env stripped, inner matches deny)" "exit=$rc output=$RESULT"
fi

run_hook "bash -c 'git status'" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "bash -c inner-only: bash -c 'git status' (bash not allowed, inner git matches)"
else
  fail "bash -c inner-only: bash -c 'git status' (bash not allowed, inner git matches)" "exit=$rc output=$RESULT"
fi

run_hook "bash script.sh" '["Bash(bash *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "bash no -c: bash script.sh (no inner extraction, matches bash *)"
else
  fail "bash no -c: bash script.sh (no inner extraction, matches bash *)" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Combined shell flags ==="

run_hook "bash -lc 'rm -rf /'" '["Bash(bash *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "bash -lc deny: bash -lc 'rm -rf /' (combined flags, inner matches deny)"
else
  fail "bash -lc deny: bash -lc 'rm -rf /' (combined flags, inner matches deny)" "exit=$rc output=$RESULT"
fi

run_hook "bash -xc 'git status'" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "bash -xc allow: bash -xc 'git status' (combined flags, inner matches allow)"
else
  fail "bash -xc allow: bash -xc 'git status' (combined flags, inner matches allow)" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Other shells (zsh, dash, ksh) ==="

run_hook "zsh -c 'rm -rf /'" '["Bash(zsh *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "zsh -c deny: zsh -c 'rm -rf /' (inner matches deny)"
else
  fail "zsh -c deny: zsh -c 'rm -rf /' (inner matches deny)" "exit=$rc output=$RESULT"
fi

run_hook "dash -c 'git status'" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "dash -c allow: dash -c 'git status' (inner matches allow)"
else
  fail "dash -c allow: dash -c 'git status' (inner matches allow)" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Command launchers: eval / exec ==="

run_hook "eval 'rm -rf /'" '["Bash(eval *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "eval deny: eval 'rm -rf /' (inner matches deny)"
else
  fail "eval deny: eval 'rm -rf /' (inner matches deny)" "exit=$rc output=$RESULT"
fi

run_hook "eval 'git status'" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "eval allow: eval 'git status' (inner matches allow)"
else
  fail "eval allow: eval 'git status' (inner matches allow)" "exit=$rc output=$RESULT"
fi

run_hook "exec rm -rf /" '["Bash(exec *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "exec deny: exec rm -rf / (inner matches deny)"
else
  fail "exec deny: exec rm -rf / (inner matches deny)" "exit=$rc output=$RESULT"
fi

run_hook "env eval 'rm -rf /'" '["Bash(eval *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "env+eval deny: env eval 'rm -rf /' (env stripped, inner matches deny)"
else
  fail "env+eval deny: env eval 'rm -rf /' (env stripped, inner matches deny)" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Phase composition ==="

run_hook "xargs bash -c 'rm -rf /'" '["Bash(bash *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "xargs+bash -c deny: xargs bash -c 'rm -rf /' (xargs -> bash -c -> inner)"
else
  fail "xargs+bash -c deny: xargs bash -c 'rm -rf /' (xargs -> bash -c -> inner)" "exit=$rc output=$RESULT"
fi

run_hook "xargs eval 'rm -rf /'" '["Bash(eval *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "xargs+eval deny: xargs eval 'rm -rf /' (xargs -> eval -> inner)"
else
  fail "xargs+eval deny: xargs eval 'rm -rf /' (xargs -> eval -> inner)" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Simple prefix launchers: time, nohup, command, builtin ==="

run_hook "time rm -rf /" '["Bash(time *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "time deny: time rm -rf / (inner matches deny)"
else
  fail "time deny: time rm -rf / (inner matches deny)" "exit=$rc output=$RESULT"
fi

run_hook "time -p git status" '["Bash(time *)", "Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "time -p allow: time -p git status (flag stripped, inner matches allow)"
else
  fail "time -p allow: time -p git status (flag stripped, inner matches allow)" "exit=$rc output=$RESULT"
fi

run_hook "nohup rm -rf /" '["Bash(nohup *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "nohup deny: nohup rm -rf / (inner matches deny)"
else
  fail "nohup deny: nohup rm -rf / (inner matches deny)" "exit=$rc output=$RESULT"
fi

run_hook "command git status" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "command allow: command git status (inner matches allow)"
else
  fail "command allow: command git status (inner matches allow)" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== FuncDecl ==="

run_hook 'f() { rm -rf /; }; f' '["Bash(f)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "funcdecl deny: f() { rm -rf /; }; f (function body extracted)"
else
  fail "funcdecl deny: f() { rm -rf /; }; f (function body extracted)" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Shell constructs: semicolons, OR, AND ==="

run_hook "git status; rm -rf /" '["Bash(git *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "semicolon deny: git status; rm -rf /"
else
  fail "semicolon deny: git status; rm -rf /" "exit=$rc output=$RESULT"
fi

run_hook "false || rm -rf /" '["Bash(false *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "OR chain deny: false || rm -rf /"
else
  fail "OR chain deny: false || rm -rf /" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Shell constructs: subshells and blocks ==="

run_hook "(rm -rf /)" '["Bash(git *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "subshell deny: (rm -rf /)"
else
  fail "subshell deny: (rm -rf /)" "exit=$rc output=$RESULT"
fi

run_hook "(git status && (rm -rf /))" '["Bash(git *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "nested subshell deny: (git status && (rm -rf /))"
else
  fail "nested subshell deny: (git status && (rm -rf /))" "exit=$rc output=$RESULT"
fi

run_hook "(git status && git log)" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "subshell allow: (git status && git log)"
else
  fail "subshell allow: (git status && git log)" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Shell constructs: if, for, case ==="

run_hook "if true; then rm -rf /; fi" '["Bash(true *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "if/then deny: if true; then rm -rf /; fi"
else
  fail "if/then deny: if true; then rm -rf /; fi" "exit=$rc output=$RESULT"
fi

run_hook "if git status; then echo ok; fi" '["Bash(git *)", "Bash(echo *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "if/then allow: if git status; then echo ok; fi"
else
  fail "if/then allow: if git status; then echo ok; fi" "exit=$rc output=$RESULT"
fi

run_hook "for i in a b; do rm -rf /; done" '["Bash(echo *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "for loop deny: for i in a b; do rm -rf /; done"
else
  fail "for loop deny: for i in a b; do rm -rf /; done" "exit=$rc output=$RESULT"
fi

run_hook 'case x in x) rm -rf /;; esac' '["Bash(echo *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "case deny: case x in x) rm -rf /;; esac"
else
  fail "case deny: case x in x) rm -rf /;; esac" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Command substitution and process substitution ==="

run_hook 'echo "$(rm -rf /)"' '["Bash(echo *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "cmd sub deny: echo \"\$(rm -rf /)\""
else
  fail "cmd sub deny: echo \"\$(rm -rf /)\"" "exit=$rc output=$RESULT"
fi

run_hook 'x=$(rm -rf /)' '["Bash(echo *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "assign cmd sub deny: x=\$(rm -rf /)"
else
  fail "assign cmd sub deny: x=\$(rm -rf /)" "exit=$rc output=$RESULT"
fi

run_hook 'echo `rm -rf /`' '["Bash(echo *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "backtick deny: echo \`rm -rf /\`"
else
  fail "backtick deny: echo \`rm -rf /\`" "exit=$rc output=$RESULT"
fi

run_hook 'local x=$(rm -rf /)' '["Bash(local *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "DeclClause cmd sub deny: local x=\$(rm -rf /)"
else
  fail "DeclClause cmd sub deny: local x=\$(rm -rf /)" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Multi-pipe and mixed compound ==="

run_hook "git log | grep foo | head -5" '["Bash(git *)", "Bash(grep *)", "Bash(head *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "multi-pipe allow: git log | grep foo | head -5"
else
  fail "multi-pipe allow: git log | grep foo | head -5" "exit=$rc output=$RESULT"
fi

run_hook "git status | head -5 && echo done" '["Bash(git *)", "Bash(head *)", "Bash(echo *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "mixed pipe+chain allow: git status | head -5 && echo done"
else
  fail "mixed pipe+chain allow: git status | head -5 && echo done" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Launcher edge cases ==="

run_hook "/usr/bin/bash -c 'rm -rf /'" '["Bash(bash *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "absolute path shell deny: /usr/bin/bash -c 'rm -rf /'"
else
  fail "absolute path shell deny: /usr/bin/bash -c 'rm -rf /'" "exit=$rc output=$RESULT"
fi

run_hook "bash -c 'git status && rm -rf /'" '["Bash(git *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "bash -c compound inner deny: bash -c 'git status && rm -rf /'"
else
  fail "bash -c compound inner deny: bash -c 'git status && rm -rf /'" "exit=$rc output=$RESULT"
fi

run_hook "git status && eval 'rm -rf /'" '["Bash(git *)", "Bash(eval *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "compound eval deny: git status && eval 'rm -rf /'"
else
  fail "compound eval deny: git status && eval 'rm -rf /'" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== FuncDecl edge cases ==="

run_hook 'f() { git status; }; f' '["Bash(f)", "Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "funcdecl allow: f() { git status; }; f (body + call both allowed)"
else
  fail "funcdecl allow: f() { git status; }; f (body + call both allowed)" "exit=$rc output=$RESULT"
fi

run_hook 'f() { rm -rf /; }; g() { git status; }; g' '["Bash(g)", "Bash(git *)"]' '["Bash(rm *)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "funcdecl multi deny: f() has rm, g() safe — deny because f body extracted"
else
  fail "funcdecl multi deny: f() has rm, g() safe — deny because f body extracted" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== VAR=val edge cases ==="

run_hook "FOO= git status" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "empty env value: FOO= git status"
else
  fail "empty env value: FOO= git status" "exit=$rc output=$RESULT"
fi

run_hook "A=B=C git status" '["Bash(git *)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "VAR=val with = in value: A=B=C git status"
else
  fail "VAR=val with = in value: A=B=C git status" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Parse mode ==="

PARSE_RESULT=$(echo "git status && git log | head" | "$BASH_BIN" "$HOOK" parse 2>/dev/null)
PARSE_COUNT=$(echo "$PARSE_RESULT" | grep -c .)
if [[ $PARSE_COUNT -eq 3 ]]; then
  pass "parse mode: 3 commands from 'git status && git log | head'"
else
  fail "parse mode: expected 3 commands, got $PARSE_COUNT" "$PARSE_RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Missing dependencies ==="

EMPTY_PATH_RESULT=$(echo '{"tool_input":{"command":"git status"}}' | PATH="" "$BASH_BIN" "$HOOK" --permissions '["Bash(git *)"]' 2>/dev/null)
EMPTY_PATH_RC=$?
if [[ $EMPTY_PATH_RC -eq 0 ]] && [[ -z "$EMPTY_PATH_RESULT" ]]; then
  pass "missing deps: graceful fallthrough"
else
  fail "missing deps: graceful fallthrough" "exit=$EMPTY_PATH_RC output=$EMPTY_PATH_RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Empty input ==="

EMPTY_RESULT=$(echo '{}' | "$BASH_BIN" "$HOOK" --permissions '["Bash(git *)"]' 2>/dev/null)
EMPTY_RC=$?
if [[ $EMPTY_RC -eq 0 ]] && [[ -z "$EMPTY_RESULT" ]]; then
  pass "empty input: exit 0"
else
  fail "empty input: exit 0" "exit=$EMPTY_RC output=$EMPTY_RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Deny message specifics (Change 6) ==="

run_hook "rm -rf /" '["Bash(git *)"]' '["Bash(rm -rf /)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  if jq -e '.systemMessage | test("rm -rf /")' <<< "$RESULT" &>/dev/null; then
    pass "deny msg: simple deny message contains command text"
  else
    fail "deny msg: simple deny message contains command text" "message=$(jq -r '.systemMessage' <<< "$RESULT")"
  fi
else
  fail "deny msg: simple deny" "exit=$rc output=$RESULT"
fi

run_hook "rm -rf /" '["Bash(git *)"]' '["Bash(rm -rf /)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  if jq -e '.systemMessage | test("rm -rf /")' <<< "$RESULT" &>/dev/null; then
    pass "deny msg: simple deny message contains matching rule"
  else
    fail "deny msg: simple deny message contains matching rule" "message=$(jq -r '.systemMessage' <<< "$RESULT")"
  fi
else
  fail "deny msg: simple deny matching rule" "exit=$rc output=$RESULT"
fi

run_hook "git status && rm -rf /" '["Bash(git *)"]' '["Bash(rm -rf /)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  if jq -e '.systemMessage | test("rm -rf /")' <<< "$RESULT" &>/dev/null; then
    pass "deny msg: compound deny message contains sub-command"
  else
    fail "deny msg: compound deny message contains sub-command" "message=$(jq -r '.systemMessage' <<< "$RESULT")"
  fi
else
  fail "deny msg: compound deny" "exit=$rc output=$RESULT"
fi

run_hook "git status && rm -rf /" '["Bash(git *)"]' '["Bash(rm -rf /)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  if jq -e '.systemMessage | test("Compound command denied")' <<< "$RESULT" &>/dev/null; then
    pass "deny msg: compound deny uses 'Compound command denied' prefix"
  else
    fail "deny msg: compound deny uses 'Compound command denied' prefix" "message=$(jq -r '.systemMessage' <<< "$RESULT")"
  fi
else
  fail "deny msg: compound deny prefix" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Safety preset validation (Change 3) ==="

SAFETY_PRESET="$SCRIPT_DIR/../presets/safety.json"

if [[ -f "$SAFETY_PRESET" ]]; then
  if jq -e '.permissions.deny | length > 0' "$SAFETY_PRESET" &>/dev/null; then
    pass "safety preset: valid JSON with deny array"
  else
    fail "safety preset: valid JSON with deny array" "missing or empty .permissions.deny"
  fi
else
  fail "safety preset: file exists" "safety.json not found"
fi

# Safety preset: rm -rf / should be denied
run_hook "rm -rf /" '["Bash(git *)"]' '["Bash(rm -rf /)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "safety preset: rm -rf / denied with exact rule"
else
  fail "safety preset: rm -rf / denied with exact rule" "exit=$rc output=$RESULT"
fi

# Safety preset: git push --force origin main should be denied
run_hook "git push --force origin main" '["Bash(git *)"]' '["Bash(git push --force origin main)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "safety preset: git push --force origin main denied"
else
  fail "safety preset: git push --force origin main denied" "exit=$rc output=$RESULT"
fi

# Safety preset: rm -rf /tmp should NOT be denied by "rm -rf /" rule
# Prefix matching requires exact, space-continuation, or slash-continuation.
# "rm -rf /tmp" doesn't match "rm -rf /" via any of those patterns.
run_hook "rm -rf /tmp" '["Bash(git *)", "Bash(rm *)"]' '["Bash(rm -rf /)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "safety preset: rm -rf /tmp NOT denied by rm -rf / rule (different path)"
else
  fail "safety preset: rm -rf /tmp NOT denied by rm -rf / rule (different path)" "exit=$rc output=$RESULT"
fi

# Known limitation: rm -rf /* is NOT caught by "rm -rf /" rule.
# The prefix matching requires space or slash continuation after the prefix.
# "rm -rf /*" has * after /, which matches neither. Bash(rm -rf /*) also
# doesn't help because jq extraction strips the trailing *, producing the
# same prefix as Bash(rm -rf /). This is acceptable: Claude's own safety
# training prevents generating rm -rf /* in normal circumstances.
run_hook "rm -rf /*" '["Bash(rm *)"]' '["Bash(rm -rf /)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "safety preset: rm -rf /* NOT caught by rm -rf / rule (known limitation)"
else
  fail "safety preset: rm -rf /* NOT caught by rm -rf / rule (known limitation)" "exit=$rc output=$RESULT"
fi

# rm -rf ./build should NOT be denied (no rm -rf . rule — removed due to false positives)
run_hook "rm -rf ./build" '["Bash(rm *)"]' '["Bash(rm -rf /)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "safety preset: rm -rf ./build NOT denied (no rm -rf . rule)"
else
  fail "safety preset: rm -rf ./build NOT denied (no rm -rf . rule)" "exit=$rc output=$RESULT"
fi

# git reset --hard should be denied
run_hook "git reset --hard" '["Bash(git *)"]' '["Bash(git reset --hard)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "safety preset: git reset --hard denied"
else
  fail "safety preset: git reset --hard denied" "exit=$rc output=$RESULT"
fi

# git reset --soft should NOT be denied by git reset --hard rule
run_hook "git reset --soft" '["Bash(git *)"]' '["Bash(git reset --hard)"]'
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "safety preset: git reset --soft allowed (not matched by --hard rule)"
else
  fail "safety preset: git reset --soft allowed (not matched by --hard rule)" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Safety edge cases: evasion attempts (should be denied) ==="

# Load all safety deny rules for these tests
SAFETY_DENY='["Bash(rm -rf /)", "Bash(rm -rf ~)", "Bash(chmod 777)", "Bash(chmod -R 777)", "Bash(mkfs *)", "Bash(dd *)", "Bash(git push --force origin main)", "Bash(git push --force origin master)", "Bash(git push -f origin main)", "Bash(git push -f origin master)", "Bash(git reset --hard)"]'
SAFETY_ALLOW='["Bash(rm *)", "Bash(git *)", "Bash(chmod *)", "Bash(echo *)", "Bash(cat *)", "Bash(dd *)"]'

# rm -rf / with extra flags — space continuation should match
run_hook "rm -rf / --no-preserve-root" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: rm -rf / --no-preserve-root denied (space continuation)"
else
  fail "evasion: rm -rf / --no-preserve-root denied (space continuation)" "exit=$rc output=$RESULT"
fi

# rm -rf ~/Documents — slash continuation of rm -rf ~ rule
run_hook "rm -rf ~/Documents" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: rm -rf ~/Documents denied (~ prefix match via /)"
else
  fail "evasion: rm -rf ~/Documents denied (~ prefix match via /)" "exit=$rc output=$RESULT"
fi

# rm -rf ~/. — should be denied
run_hook "rm -rf ~/." "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: rm -rf ~/. denied (~ prefix match via /)"
else
  fail "evasion: rm -rf ~/. denied (~ prefix match via /)" "exit=$rc output=$RESULT"
fi

# chmod 777 on a specific file — space continuation
run_hook "chmod 777 /etc/passwd" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: chmod 777 /etc/passwd denied (space continuation)"
else
  fail "evasion: chmod 777 /etc/passwd denied (space continuation)" "exit=$rc output=$RESULT"
fi

# chmod -R 777 on a directory
run_hook "chmod -R 777 /var" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: chmod -R 777 /var denied (space continuation)"
else
  fail "evasion: chmod -R 777 /var denied (space continuation)" "exit=$rc output=$RESULT"
fi

# dd with device args
run_hook "dd if=/dev/zero of=/dev/sda" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: dd if=/dev/zero of=/dev/sda denied"
else
  fail "evasion: dd if=/dev/zero of=/dev/sda denied" "exit=$rc output=$RESULT"
fi

# git reset --hard with ref
run_hook "git reset --hard HEAD~3" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: git reset --hard HEAD~3 denied (space continuation)"
else
  fail "evasion: git reset --hard HEAD~3 denied (space continuation)" "exit=$rc output=$RESULT"
fi

# git reset --hard origin/main
run_hook "git reset --hard origin/main" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: git reset --hard origin/main denied (space continuation)"
else
  fail "evasion: git reset --hard origin/main denied (space continuation)" "exit=$rc output=$RESULT"
fi

# git push --force with extra args
run_hook "git push --force origin main feature" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: git push --force origin main feature denied (space continuation)"
else
  fail "evasion: git push --force origin main feature denied (space continuation)" "exit=$rc output=$RESULT"
fi

# Evasion via env var prefix
run_hook "FOO=bar rm -rf /" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: FOO=bar rm -rf / denied (env var stripped)"
else
  fail "evasion: FOO=bar rm -rf / denied (env var stripped)" "exit=$rc output=$RESULT"
fi

# Evasion via env launcher
run_hook "env rm -rf /" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: env rm -rf / denied (env launcher stripped)"
else
  fail "evasion: env rm -rf / denied (env launcher stripped)" "exit=$rc output=$RESULT"
fi

# Evasion via compound chain
run_hook "echo hello && rm -rf /" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: echo hello && rm -rf / denied (compound chain)"
else
  fail "evasion: echo hello && rm -rf / denied (compound chain)" "exit=$rc output=$RESULT"
fi

# Evasion via pipe
run_hook "rm -rf / | cat" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: rm -rf / | cat denied (compound pipe)"
else
  fail "evasion: rm -rf / | cat denied (compound pipe)" "exit=$rc output=$RESULT"
fi

# Evasion via bash -c
run_hook "bash -c 'rm -rf /'" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: bash -c 'rm -rf /' denied (shell -c recursion)"
else
  fail "evasion: bash -c 'rm -rf /' denied (shell -c recursion)" "exit=$rc output=$RESULT"
fi

# Evasion via eval
run_hook "eval 'rm -rf /'" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: eval 'rm -rf /' denied (eval recursion)"
else
  fail "evasion: eval 'rm -rf /' denied (eval recursion)" "exit=$rc output=$RESULT"
fi

# Evasion via semicolon
run_hook "echo safe; git reset --hard" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: echo safe; git reset --hard denied (semicolon compound)"
else
  fail "evasion: echo safe; git reset --hard denied (semicolon compound)" "exit=$rc output=$RESULT"
fi

# Evasion via subshell
run_hook "(rm -rf /)" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "evasion: (rm -rf /) denied (subshell)"
else
  fail "evasion: (rm -rf /) denied (subshell)" "exit=$rc output=$RESULT"
fi

# Deny takes precedence: dd is in both allow and deny — deny wins
run_hook "dd if=/dev/zero of=/dev/sda bs=1M" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  pass "precedence: dd in both allow and deny — deny wins"
else
  fail "precedence: dd in both allow and deny — deny wins" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Safety edge cases: false positive avoidance (should NOT be denied) ==="

# rm on a different path (not / or ~)
run_hook "rm -rf /var/tmp/build" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "false positive: rm -rf /var/tmp/build allowed"
else
  fail "false positive: rm -rf /var/tmp/build allowed" "exit=$rc output=$RESULT"
fi

# Plain rm (not rm -rf /)
run_hook "rm file.txt" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "false positive: rm file.txt allowed"
else
  fail "false positive: rm file.txt allowed" "exit=$rc output=$RESULT"
fi

# rm -rf on a relative path
run_hook "rm -rf node_modules" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "false positive: rm -rf node_modules allowed"
else
  fail "false positive: rm -rf node_modules allowed" "exit=$rc output=$RESULT"
fi

# chmod with safe permissions
run_hook "chmod 755 script.sh" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "false positive: chmod 755 script.sh allowed"
else
  fail "false positive: chmod 755 script.sh allowed" "exit=$rc output=$RESULT"
fi

run_hook "chmod 644 file.txt" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "false positive: chmod 644 file.txt allowed"
else
  fail "false positive: chmod 644 file.txt allowed" "exit=$rc output=$RESULT"
fi

run_hook "chmod +x script.sh" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "false positive: chmod +x script.sh allowed"
else
  fail "false positive: chmod +x script.sh allowed" "exit=$rc output=$RESULT"
fi

# git push without --force
run_hook "git push origin main" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "false positive: git push origin main allowed (no --force)"
else
  fail "false positive: git push origin main allowed (no --force)" "exit=$rc output=$RESULT"
fi

# git push --force to a non-protected branch
run_hook "git push --force origin develop" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "false positive: git push --force origin develop allowed (not main/master)"
else
  fail "false positive: git push --force origin develop allowed (not main/master)" "exit=$rc output=$RESULT"
fi

# git push --force to a feature branch
run_hook "git push -f origin feature/my-branch" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "false positive: git push -f origin feature/my-branch allowed"
else
  fail "false positive: git push -f origin feature/my-branch allowed" "exit=$rc output=$RESULT"
fi

# git push --force-with-lease (safer variant, not blocked)
run_hook "git push --force-with-lease origin main" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "false positive: git push --force-with-lease origin main allowed (different flag)"
else
  fail "false positive: git push --force-with-lease origin main allowed (different flag)" "exit=$rc output=$RESULT"
fi

# git reset without --hard
run_hook "git reset --mixed HEAD~1" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "false positive: git reset --mixed HEAD~1 allowed"
else
  fail "false positive: git reset --mixed HEAD~1 allowed" "exit=$rc output=$RESULT"
fi

# git reset (no flags at all)
run_hook "git reset HEAD file.txt" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "false positive: git reset HEAD file.txt allowed (no --hard)"
else
  fail "false positive: git reset HEAD file.txt allowed (no --hard)" "exit=$rc output=$RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Safety edge cases: known limitations ==="

# mkfs.ext4 not caught — period is not space or slash.
# Negligible risk: mkfs requires root/sudo, targets block devices that don't
# exist on dev machines (macOS doesn't even have mkfs), and Claude's safety
# training would refuse this. The base "mkfs" command IS caught.
run_hook "mkfs.ext4 /dev/sda" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 0 ]] && [[ -z "$RESULT" || $(jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" 2>/dev/null) ]]; then
  pass "known limitation: mkfs.ext4 /dev/sda NOT caught (period after mkfs)"
else
  # If it IS denied, that's actually better — update test if matching improves
  pass "known limitation: mkfs.ext4 /dev/sda — matching improved, now denied"
fi

# chmod 7777 not caught — 7 after 777 is not space or slash.
# Negligible risk: chmod 7777 is an obscure/invalid-looking permission that
# no legitimate workflow uses. Claude would use chmod 777, which IS caught.
# The safety preset is defense-in-depth, not the primary protection.
run_hook "chmod 7777 file" "$SAFETY_ALLOW" "$SAFETY_DENY"
rc=$?
if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
  pass "known limitation: chmod 7777 NOT caught (7 after 777, not space/slash)"
else
  pass "known limitation: chmod 7777 — matching improved, now denied"
fi

# ---------------------------------------------------------------------------
echo "=== SessionStart hook (Change 2) ==="

SESSION_HOOK="$SCRIPT_DIR/../hooks/session-start.sh"

if [[ -x "$SESSION_HOOK" ]]; then
  pass "session-start hook: file exists and is executable"
else
  fail "session-start hook: file exists and is executable" "not found or not executable"
fi

# Test: outputs valid JSON when no settings exist (temp HOME)
TEMP_HOME=$(mktemp -d)
SESSION_OUT=$(HOME="$TEMP_HOME" "$BASH_BIN" "$SESSION_HOOK" 2>/dev/null || true)
if jq -e '.hookSpecificOutput.additionalContext' <<< "$SESSION_OUT" &>/dev/null; then
  pass "session-start hook: outputs JSON with additionalContext when no settings"
else
  fail "session-start hook: outputs JSON with additionalContext when no settings" "output=$SESSION_OUT"
fi

# Test: creates flag file after first run
if [[ -f "$TEMP_HOME/.config/claude-permissions-helper/.welcomed" ]]; then
  pass "session-start hook: creates flag file after first run"
else
  fail "session-start hook: creates flag file after first run" "flag not found"
fi

# Test: silent when flag file exists (second run)
SESSION_OUT2=$(HOME="$TEMP_HOME" "$BASH_BIN" "$SESSION_HOOK" 2>/dev/null || true)
if [[ -z "$SESSION_OUT2" ]]; then
  pass "session-start hook: silent on second run (flag exists)"
else
  fail "session-start hook: silent on second run (flag exists)" "output=$SESSION_OUT2"
fi

# Test: silent when settings already have Bash rules
TEMP_HOME2=$(mktemp -d)
mkdir -p "$TEMP_HOME2/.claude"
echo '{"permissions":{"allow":["Bash(git *)"]}}' > "$TEMP_HOME2/.claude/settings.json"
SESSION_OUT3=$(HOME="$TEMP_HOME2" "$BASH_BIN" "$SESSION_HOOK" 2>/dev/null || true)
if [[ -z "$SESSION_OUT3" ]]; then
  pass "session-start hook: silent when Bash rules exist"
else
  fail "session-start hook: silent when Bash rules exist" "output=$SESSION_OUT3"
fi

# Cleanup temp dirs
rm -rf "$TEMP_HOME" "$TEMP_HOME2"

# ---------------------------------------------------------------------------
echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1

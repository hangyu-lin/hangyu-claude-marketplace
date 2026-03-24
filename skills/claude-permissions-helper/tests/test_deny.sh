#!/usr/bin/env bash
# Tests that verify commands are NOT auto-approved (deny, fallthrough, or blocked).
# Usage: bash tests/test_deny.sh
#
# Requires: jq, shfmt, bash 4.3+

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

is_fallthrough() {
  [[ $1 -eq 0 ]] && { [[ -z "$RESULT" ]] || { jq -e '.systemMessage' <<< "$RESULT" &>/dev/null && ! jq -e '.hookSpecificOutput.permissionDecision' <<< "$RESULT" &>/dev/null; }; }
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

expect_fallthrough() {
  local name="$1" cmd="$2" perms="$3" deny="${4:-}"
  run_hook "$cmd" "$perms" "$deny"
  local rc=$?
  if is_fallthrough $rc; then
    pass "$name"
  else
    fail "$name" "exit=$rc output=$RESULT"
  fi
}

# Not auto-approved: deny OR fallthrough (either is safe)
expect_not_approved() {
  local name="$1" cmd="$2" perms="$3" deny="${4:-}"
  run_hook "$cmd" "$perms" "$deny"
  local rc=$?
  if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
    fail "$name" "AUTO-APPROVED (should not be)"
  else
    pass "$name"
  fi
}

# ---------------------------------------------------------------------------
echo "=== Simple commands ==="

expect_deny "simple deny: rm -rf /" \
  "rm -rf /" '["Bash(git *)"]' '["Bash(rm *)"]'
expect_fallthrough "simple fallthrough: unknown command" \
  "unknown-cmd foo" '["Bash(git *)"]'

# ---------------------------------------------------------------------------
echo "=== Compound commands ==="

expect_deny "compound deny: git status && rm -rf /" \
  "git status && rm -rf /" '["Bash(git *)"]' '["Bash(rm *)"]'
expect_fallthrough "compound fallthrough: git status && unknown-cmd" \
  "git status && unknown-cmd" '["Bash(git *)"]'

# ---------------------------------------------------------------------------
echo "=== Newlines ==="

expect_deny "newline deny: git status\\nrm -rf /" \
  $'git status\nrm -rf /' '["Bash(git *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== Command launchers: env ==="

expect_deny "env launcher deny: env rm -rf /" \
  "env rm -rf /" '["Bash(git *)"]' '["Bash(rm *)"]'
expect_fallthrough "env launcher fallthrough: env rm -rf / (rm not allowed)" \
  "env rm -rf /" '["Bash(git *)"]'

# ---------------------------------------------------------------------------
echo "=== Command launchers: xargs ==="

expect_deny "xargs deny: xargs rm -rf" \
  "xargs rm -rf" '["Bash(git *)"]' '["Bash(rm *)"]'
expect_deny "xargs deny: xargs -I {} rm -rf {}" \
  "xargs -I {} rm -rf {}" '["Bash(git *)"]' '["Bash(rm *)"]'
expect_deny "xargs deny: xargs -- rm (-- ends opts)" \
  "xargs -- rm" '["Bash(git *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== Command launchers: combined ==="

expect_deny "pipe+xargs deny: find . | xargs rm" \
  "find . | xargs rm" '["Bash(find *)"]' '["Bash(rm *)"]'
expect_deny "env+xargs deny: env xargs -n1 rm" \
  "env xargs -n1 rm" '["Bash(git *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== Command launchers: bash -c / sh -c ==="

expect_deny "bash -c deny: inner matches deny" \
  "bash -c 'rm -rf /'" '["Bash(bash *)"]' '["Bash(rm *)"]'
expect_deny "sh -c deny: inner matches deny" \
  "sh -c 'rm -rf /'" '["Bash(sh *)"]' '["Bash(rm *)"]'
expect_deny "env+bash -c deny: env stripped, inner matches deny" \
  "env bash -c 'rm -rf /'" '["Bash(bash *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== Combined shell flags ==="

expect_deny "bash -lc deny: combined flags, inner matches deny" \
  "bash -lc 'rm -rf /'" '["Bash(bash *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== Other shells ==="

expect_deny "zsh -c deny: inner matches deny" \
  "zsh -c 'rm -rf /'" '["Bash(zsh *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== Command launchers: eval / exec ==="

expect_deny "eval deny: inner matches deny" \
  "eval 'rm -rf /'" '["Bash(eval *)"]' '["Bash(rm *)"]'
expect_deny "exec deny: inner matches deny" \
  "exec rm -rf /" '["Bash(exec *)"]' '["Bash(rm *)"]'
expect_deny "env+eval deny: env stripped, inner matches deny" \
  "env eval 'rm -rf /'" '["Bash(eval *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== Phase composition ==="

expect_deny "xargs+bash -c deny: xargs -> bash -c -> inner" \
  "xargs bash -c 'rm -rf /'" '["Bash(bash *)"]' '["Bash(rm *)"]'
expect_deny "xargs+eval deny: xargs -> eval -> inner" \
  "xargs eval 'rm -rf /'" '["Bash(eval *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== Simple prefix launchers ==="

expect_deny "time deny: inner matches deny" \
  "time rm -rf /" '["Bash(time *)"]' '["Bash(rm *)"]'
expect_deny "nohup deny: inner matches deny" \
  "nohup rm -rf /" '["Bash(nohup *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== FuncDecl ==="

expect_deny "funcdecl deny: f() { rm -rf /; }; f" \
  'f() { rm -rf /; }; f' '["Bash(f)"]' '["Bash(rm *)"]'
expect_deny "funcdecl multi deny: f() has rm, g() safe" \
  'f() { rm -rf /; }; g() { git status; }; g' '["Bash(g)", "Bash(git *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== Shell constructs: semicolons, OR, AND ==="

expect_deny "semicolon deny: git status; rm -rf /" \
  "git status; rm -rf /" '["Bash(git *)"]' '["Bash(rm *)"]'
expect_deny "OR chain deny: false || rm -rf /" \
  "false || rm -rf /" '["Bash(false *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== Shell constructs: subshells and blocks ==="

expect_deny "subshell deny: (rm -rf /)" \
  "(rm -rf /)" '["Bash(git *)"]' '["Bash(rm *)"]'
expect_deny "nested subshell deny: (git status && (rm -rf /))" \
  "(git status && (rm -rf /))" '["Bash(git *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== Shell constructs: if, for, case ==="

expect_deny "if/then deny: if true; then rm -rf /; fi" \
  "if true; then rm -rf /; fi" '["Bash(true *)"]' '["Bash(rm *)"]'
expect_deny "for loop deny: for i in a b; do rm -rf /; done" \
  "for i in a b; do rm -rf /; done" '["Bash(echo *)"]' '["Bash(rm *)"]'
expect_deny "case deny: case x in x) rm -rf /;; esac" \
  'case x in x) rm -rf /;; esac' '["Bash(echo *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== Command substitution and process substitution ==="

expect_deny 'cmd sub deny: echo "$(rm -rf /)"' \
  'echo "$(rm -rf /)"' '["Bash(echo *)"]' '["Bash(rm *)"]'
expect_deny 'assign cmd sub deny: x=$(rm -rf /)' \
  'x=$(rm -rf /)' '["Bash(echo *)"]' '["Bash(rm *)"]'
expect_deny 'backtick deny: echo `rm -rf /`' \
  'echo `rm -rf /`' '["Bash(echo *)"]' '["Bash(rm *)"]'
expect_deny 'DeclClause cmd sub deny: local x=$(rm -rf /)' \
  'local x=$(rm -rf /)' '["Bash(local *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== Launcher edge cases ==="

expect_deny "absolute path shell deny: /usr/bin/bash -c 'rm -rf /'" \
  "/usr/bin/bash -c 'rm -rf /'" '["Bash(bash *)"]' '["Bash(rm *)"]'
expect_deny "bash -c compound inner deny" \
  "bash -c 'git status && rm -rf /'" '["Bash(git *)"]' '["Bash(rm *)"]'
expect_deny "compound eval deny: git status && eval 'rm -rf /'" \
  "git status && eval 'rm -rf /'" '["Bash(git *)", "Bash(eval *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== Absolute path normalization (deny) ==="

expect_deny "abspath deny: /bin/rm -rf /" \
  "/bin/rm -rf /" '["Bash(rm *)"]' '["Bash(rm -rf /)"]'
expect_deny "abspath deny: /opt/.../bash -c 'rm -rf /' → inner denied" \
  "/opt/homebrew/bin/bash -c 'rm -rf /'" '["Bash(bash *)"]' '["Bash(rm -rf /)"]'

# ---------------------------------------------------------------------------
echo "=== Deny message specifics ==="

run_hook "rm -rf /" '["Bash(git *)"]' '["Bash(rm -rf /)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  if jq -e '.systemMessage | test("rm -rf /")' <<< "$RESULT" &>/dev/null; then
    pass "deny msg: contains command text"
  else
    fail "deny msg: contains command text" "message=$(jq -r '.systemMessage' <<< "$RESULT")"
  fi
else
  fail "deny msg: simple deny" "exit=$rc"
fi

run_hook "git status && rm -rf /" '["Bash(git *)"]' '["Bash(rm -rf /)"]'
rc=$?
if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
  if jq -e '.systemMessage | test("Compound command denied")' <<< "$RESULT" &>/dev/null; then
    pass "deny msg: compound uses 'Compound command denied' prefix"
  else
    fail "deny msg: compound uses 'Compound command denied' prefix" "message=$(jq -r '.systemMessage' <<< "$RESULT")"
  fi
else
  fail "deny msg: compound deny" "exit=$rc"
fi

# ---------------------------------------------------------------------------
echo "=== Safety preset validation ==="

SAFETY_PRESET="$SCRIPT_DIR/../presets/safety.json"
if [[ -f "$SAFETY_PRESET" ]] && jq -e '.permissions.deny | length > 0' "$SAFETY_PRESET" &>/dev/null; then
  pass "safety preset: valid JSON with deny array"
else
  fail "safety preset: valid JSON with deny array" "missing or empty"
fi

expect_deny "safety: rm -rf / denied" \
  "rm -rf /" '["Bash(git *)"]' '["Bash(rm -rf /)"]'
expect_deny "safety: git push --force origin main denied" \
  "git push --force origin main" '["Bash(git *)"]' '["Bash(git push --force origin main)"]'
expect_deny "safety: git reset --hard denied" \
  "git reset --hard" '["Bash(git *)"]' '["Bash(git reset --hard)"]'

# ---------------------------------------------------------------------------
echo "=== Safety: evasion attempts (should be denied) ==="

SAFETY_DENY='["Bash(rm -rf /)", "Bash(rm -rf ~)", "Bash(chmod 777)", "Bash(chmod -R 777)", "Bash(mkfs *)", "Bash(dd *)", "Bash(git push --force origin main)", "Bash(git push --force origin master)", "Bash(git push -f origin main)", "Bash(git push -f origin master)", "Bash(git reset --hard)"]'
SAFETY_ALLOW='["Bash(rm *)", "Bash(git *)", "Bash(chmod *)", "Bash(echo *)", "Bash(cat *)", "Bash(dd *)"]'

expect_deny "evasion: rm -rf / --no-preserve-root" \
  "rm -rf / --no-preserve-root" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: rm -rf ~/Documents" \
  "rm -rf ~/Documents" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: rm -rf ~/." \
  "rm -rf ~/." "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: chmod 777 /etc/passwd" \
  "chmod 777 /etc/passwd" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: chmod -R 777 /var" \
  "chmod -R 777 /var" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: dd if=/dev/zero of=/dev/sda" \
  "dd if=/dev/zero of=/dev/sda" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: git reset --hard HEAD~3" \
  "git reset --hard HEAD~3" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: git reset --hard origin/main" \
  "git reset --hard origin/main" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: git push --force origin main feature" \
  "git push --force origin main feature" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: FOO=bar rm -rf / (env var stripped)" \
  "FOO=bar rm -rf /" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: env rm -rf / (env launcher stripped)" \
  "env rm -rf /" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: echo hello && rm -rf / (compound chain)" \
  "echo hello && rm -rf /" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: rm -rf / | cat (compound pipe)" \
  "rm -rf / | cat" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: bash -c 'rm -rf /' (shell -c recursion)" \
  "bash -c 'rm -rf /'" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: eval 'rm -rf /' (eval recursion)" \
  "eval 'rm -rf /'" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: echo safe; git reset --hard (semicolon)" \
  "echo safe; git reset --hard" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "evasion: (rm -rf /) (subshell)" \
  "(rm -rf /)" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_deny "precedence: dd in both allow and deny — deny wins" \
  "dd if=/dev/zero of=/dev/sda bs=1M" "$SAFETY_ALLOW" "$SAFETY_DENY"

# ---------------------------------------------------------------------------
echo "=== SECURITY: nested launcher deny bypass ==="

BYPASS_ALLOW='["Bash(command *)", "Bash(rm *)", "Bash(echo *)", "Bash(sh *)"]'
BYPASS_DENY='["Bash(rm -rf /)", "Bash(rm -rf ~)", "Bash(chmod 777)"]'

expect_deny "SECURITY: command sh -c 'rm -rf /'" \
  "command sh -c 'rm -rf /'" "$BYPASS_ALLOW" "$BYPASS_DENY"
expect_deny "SECURITY: command -p sh -c 'rm -rf /'" \
  "command -p sh -c 'rm -rf /'" "$BYPASS_ALLOW" "$BYPASS_DENY"
expect_deny "SECURITY: command eval 'rm -rf /'" \
  "command eval 'rm -rf /'" '["Bash(command *)", "Bash(eval *)", "Bash(rm *)"]' "$BYPASS_DENY"
expect_deny "SECURITY: command command rm -rf /" \
  "command command rm -rf /" '["Bash(command *)"]' "$BYPASS_DENY"
expect_deny "SECURITY: nohup sh -c 'rm -rf /'" \
  "nohup sh -c 'rm -rf /'" '["Bash(nohup *)", "Bash(rm *)"]' "$BYPASS_DENY"
expect_deny "SECURITY: time sh -c 'rm -rf /'" \
  "time sh -c 'rm -rf /'" '["Bash(time *)", "Bash(rm *)"]' "$BYPASS_DENY"
expect_deny "SECURITY: echo | command sh -c 'rm -rf /' (compound)" \
  "echo hello | command sh -c 'rm -rf /'" "$BYPASS_ALLOW" "$BYPASS_DENY"

# ---------------------------------------------------------------------------
echo "=== SECURITY: command * edge cases (deny) ==="

expect_deny "command rm -rf / (single layer)" \
  "command rm -rf /" '["Bash(command *)"]' "$BYPASS_DENY"
expect_deny "command -p rm -rf / (single layer+flag)" \
  "command -p rm -rf /" '["Bash(command *)"]' "$BYPASS_DENY"

# ---------------------------------------------------------------------------
echo "=== SECURITY: xargs * edge cases ==="

XARGS_ALLOW='["Bash(xargs *)", "Bash(cat *)", "Bash(find *)", "Bash(echo *)"]'
XARGS_DENY='["Bash(rm -rf /)", "Bash(rm -rf ~)", "Bash(chmod 777)"]'

expect_not_approved "SECURITY: xargs -I{} sh -c '{}' (opaque placeholder)" \
  "xargs -I{} sh -c '{}'" '["Bash(xargs *)"]' "$XARGS_DENY"
expect_not_approved "SECURITY: xargs -I {} sh -c '{}' (space-separated)" \
  "xargs -I {} sh -c '{}'" '["Bash(xargs *)"]' "$XARGS_DENY"
expect_deny "SECURITY: find / | xargs rm -rf /" \
  "find / | xargs rm -rf /" '["Bash(find *)", "Bash(xargs *)", "Bash(rm *)"]' "$XARGS_DENY"
expect_deny "SECURITY: xargs sh -c 'rm -rf /'" \
  "xargs sh -c 'rm -rf /'" '["Bash(xargs *)", "Bash(sh *)", "Bash(rm *)"]' "$XARGS_DENY"
expect_deny "SECURITY: FOO=bar xargs rm -rf /" \
  "FOO=bar xargs rm -rf /" '["Bash(xargs *)", "Bash(rm *)"]' "$XARGS_DENY"

# ---------------------------------------------------------------------------
echo "=== SECURITY: env flag bypass ==="

ENV_ALLOW='["Bash(env *)", "Bash(bash *)", "Bash(sh *)", "Bash(rm *)", "Bash(git *)"]'
ENV_DENY='["Bash(rm -rf /)", "Bash(rm -rf ~)", "Bash(chmod 777)"]'

expect_deny "SECURITY: env -i bash -c 'rm -rf /'" \
  "env -i bash -c 'rm -rf /'" "$ENV_ALLOW" "$ENV_DENY"
expect_deny "SECURITY: env -u PATH rm -rf /" \
  "env -u PATH rm -rf /" "$ENV_ALLOW" "$ENV_DENY"
expect_deny "SECURITY: env -- rm -rf /" \
  "env -- rm -rf /" "$ENV_ALLOW" "$ENV_DENY"
expect_deny "SECURITY: env -i FOO=bar rm -rf /" \
  "env -i FOO=bar rm -rf /" "$ENV_ALLOW" "$ENV_DENY"

# ---------------------------------------------------------------------------
echo "=== Infrastructure: parse mode ==="

PARSE_RESULT=$(echo "git status && git log | head" | "$BASH_BIN" "$HOOK" parse 2>/dev/null)
PARSE_COUNT=$(echo "$PARSE_RESULT" | grep -c .)
if [[ $PARSE_COUNT -eq 3 ]]; then
  pass "parse mode: 3 commands from 'git status && git log | head'"
else
  fail "parse mode: expected 3 commands, got $PARSE_COUNT" "$PARSE_RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Infrastructure: missing dependencies ==="

EMPTY_PATH_RESULT=$(echo '{"tool_input":{"command":"git status"}}' | PATH="" "$BASH_BIN" "$HOOK" --permissions '["Bash(git *)"]' 2>/dev/null)
EMPTY_PATH_RC=$?
if [[ $EMPTY_PATH_RC -eq 0 ]] && [[ -z "$EMPTY_PATH_RESULT" ]]; then
  pass "missing deps: graceful fallthrough"
else
  fail "missing deps: graceful fallthrough" "exit=$EMPTY_PATH_RC output=$EMPTY_PATH_RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Infrastructure: empty input ==="

EMPTY_RESULT=$(echo '{}' | "$BASH_BIN" "$HOOK" --permissions '["Bash(git *)"]' 2>/dev/null)
EMPTY_RC=$?
if [[ $EMPTY_RC -eq 0 ]] && [[ -z "$EMPTY_RESULT" ]]; then
  pass "empty input: exit 0"
else
  fail "empty input: exit 0" "exit=$EMPTY_RC output=$EMPTY_RESULT"
fi

# ---------------------------------------------------------------------------
echo "=== Infrastructure: session-start hook ==="

SESSION_HOOK="$SCRIPT_DIR/../hooks/session-start.sh"

if [[ -x "$SESSION_HOOK" ]]; then
  pass "session-start hook: exists and is executable"
else
  fail "session-start hook: exists and is executable" "not found"
fi

TEMP_HOME=$(mktemp -d)
SESSION_OUT=$(HOME="$TEMP_HOME" "$BASH_BIN" "$SESSION_HOOK" 2>/dev/null || true)
if jq -e '.hookSpecificOutput.additionalContext' <<< "$SESSION_OUT" &>/dev/null; then
  pass "session-start hook: outputs JSON when no settings"
else
  fail "session-start hook: outputs JSON when no settings" "output=$SESSION_OUT"
fi

if [[ -f "$TEMP_HOME/.config/claude-permissions-helper/.welcomed" ]]; then
  pass "session-start hook: creates flag file"
else
  fail "session-start hook: creates flag file" "flag not found"
fi

SESSION_OUT2=$(HOME="$TEMP_HOME" "$BASH_BIN" "$SESSION_HOOK" 2>/dev/null || true)
if [[ -z "$SESSION_OUT2" ]]; then
  pass "session-start hook: silent on second run"
else
  fail "session-start hook: silent on second run" "output=$SESSION_OUT2"
fi

TEMP_HOME2=$(mktemp -d)
mkdir -p "$TEMP_HOME2/.claude"
echo '{"permissions":{"allow":["Bash(git *)"]}}' > "$TEMP_HOME2/.claude/settings.json"
SESSION_OUT3=$(HOME="$TEMP_HOME2" "$BASH_BIN" "$SESSION_HOOK" 2>/dev/null || true)
if [[ -z "$SESSION_OUT3" ]]; then
  pass "session-start hook: silent when Bash rules exist"
else
  fail "session-start hook: silent when Bash rules exist" "output=$SESSION_OUT3"
fi

rm -rf "$TEMP_HOME" "$TEMP_HOME2"

# ---------------------------------------------------------------------------
echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1

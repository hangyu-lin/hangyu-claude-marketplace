#!/usr/bin/env bash
# Unit tests: commands that should auto-approve (allow decision).
# Basic, wrapper, and nested cases only. E2e coverage is in test_e2e.sh.
#
# Usage: bash tests/test_allow.sh

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/test_helpers.sh"

ALLOW='["Bash(git *)", "Bash(echo *)", "Bash(head *)", "Bash(grep *)", "Bash(date *)", "Bash(curl *)", "Bash(wc *)"]'

# ---------------------------------------------------------------------------
echo "=== Basic ==="

expect_allow "simple command" "git status" "$ALLOW"
expect_allow "command with args" "git log --oneline -10" "$ALLOW"
expect_allow "pipe" "git log | head -20" "$ALLOW"
expect_allow "chain (&&)" "git status && git log" "$ALLOW"
expect_allow "semicolon" "git status; echo done" "$ALLOW"
expect_allow "subshell" "(git status && git log)" "$ALLOW"
expect_allow "command substitution" 'echo "$(date)"' "$ALLOW"
expect_allow "multi-pipe" "git log | grep foo | head -5" "$ALLOW"
expect_allow "if/then" "if git status; then echo ok; fi" "$ALLOW"

# ---------------------------------------------------------------------------
echo "=== Env var stripping ==="

expect_allow "single env var" "FOO=bar git status" "$ALLOW"
expect_allow "quoted env var" 'FOO="hello world" git status' "$ALLOW"
expect_allow "multiple env vars" "A=1 B=2 git status" "$ALLOW"

# ---------------------------------------------------------------------------
echo "=== Wrapper stripping ==="

expect_allow "env" "env git status" "$ALLOW"
expect_allow "env with vars" "env FOO=bar git status" "$ALLOW"
expect_allow "bash -c" "bash -c 'git status'" "$ALLOW"
expect_allow "sh -c" "sh -c 'git log --oneline'" "$ALLOW"
expect_allow "bash -xc (combined flags)" "bash -xc 'git status'" "$ALLOW"
expect_allow "dash -c" "dash -c 'git status'" "$ALLOW"
expect_allow "eval" "eval 'git status'" "$ALLOW"
expect_allow "exec" "exec git status" "$ALLOW"
expect_allow "trap" "trap 'echo cleanup' EXIT" "$ALLOW"
expect_allow "time" "time git status" "$ALLOW"
expect_allow "command" "command git status" "$ALLOW"
expect_allow "xargs" "xargs -n1 curl" "$ALLOW"
expect_allow "absolute path" "/usr/bin/git status" "$ALLOW"

# ---------------------------------------------------------------------------
echo "=== Nested wrappers ==="

expect_allow "env + bash -c" "env bash -c 'git status'" "$ALLOW"
expect_allow "command + bash -c" "command bash -c 'git status'" "$ALLOW"
expect_allow "time + bash -c" "time bash -c 'git status'" "$ALLOW"
expect_allow "nohup + env" "nohup env git status" '["Bash(git *)", "Bash(nohup *)"]'
expect_allow "env + exec + bash -c" "env exec bash -c 'git status'" "$ALLOW"
expect_allow "bash -c compound inner" "bash -c 'git status && git log'" "$ALLOW"

# ---------------------------------------------------------------------------
echo "=== Deny rule does not false-positive ==="

DENY='["Bash(rm -rf /)", "Bash(git reset --hard)", "Bash(git push --force origin main)"]'
expect_allow "rm -rf /tmp (not root)" "rm -rf /tmp" '["Bash(rm *)"]' "$DENY"
expect_allow "rm -rf ./build (relative)" "rm -rf ./build" '["Bash(rm *)"]' "$DENY"
expect_allow "git reset --soft (not --hard)" "git reset --soft HEAD~1" '["Bash(git *)"]' "$DENY"
expect_allow "git push origin main (no --force)" "git push origin main" '["Bash(git *)"]' "$DENY"
expect_allow "git push --force origin develop (not main)" "git push --force origin develop" '["Bash(git *)"]' "$DENY"
expect_allow "git push --force-with-lease origin main" "git push --force-with-lease origin main" '["Bash(git *)"]' "$DENY"

# ---------------------------------------------------------------------------
print_results

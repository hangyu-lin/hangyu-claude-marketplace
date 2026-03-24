#!/usr/bin/env bash
# Unit tests: commands that should be actively denied.
# Basic, wrapper, and nested cases only. E2e coverage is in test_e2e.sh.
#
# Usage: bash tests/test_deny.sh

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/test_helpers.sh"

ALLOW='["Bash(git *)", "Bash(echo *)", "Bash(rm *)", "Bash(cat *)", "Bash(find *)"]'
DENY='["Bash(rm -rf /)", "Bash(rm -rf ~)", "Bash(chmod 777)", "Bash(dd *)"]'

# ---------------------------------------------------------------------------
echo "=== Basic ==="

expect_deny "simple" "rm -rf /" "$ALLOW" "$DENY"
expect_deny "with extra args" "rm -rf / --no-preserve-root" "$ALLOW" "$DENY"
expect_deny "prefix match (rm -rf ~/Documents)" "rm -rf ~/Documents" "$ALLOW" "$DENY"
expect_deny "chain (&&)" "git status && rm -rf /" "$ALLOW" "$DENY"
expect_deny "semicolon" "git status; rm -rf /" "$ALLOW" "$DENY"
expect_deny "pipe" "rm -rf / | cat" "$ALLOW" "$DENY"
expect_deny "OR chain" "false || rm -rf /" '["Bash(false *)"]' "$DENY"
expect_deny "subshell" "(rm -rf /)" "$ALLOW" "$DENY"
expect_deny "nested subshell" "(git status && (rm -rf /))" "$ALLOW" "$DENY"
expect_deny "newline injection" $'git status\nrm -rf /' "$ALLOW" "$DENY"

# ---------------------------------------------------------------------------
echo "=== Shell constructs ==="

expect_deny "if/then" "if true; then rm -rf /; fi" '["Bash(true *)"]' "$DENY"
expect_deny "for loop" "for i in a b; do rm -rf /; done" "$ALLOW" "$DENY"
expect_deny "case" 'case x in x) rm -rf /;; esac' "$ALLOW" "$DENY"
expect_deny 'command substitution' 'echo "$(rm -rf /)"' "$ALLOW" "$DENY"
expect_deny "assignment cmd sub" 'x=$(rm -rf /)' "$ALLOW" "$DENY"
expect_deny "function body" 'f() { rm -rf /; }; f' '["Bash(f)"]' "$DENY"

# ---------------------------------------------------------------------------
echo "=== Wrapper stripping ==="

expect_deny "env" "env rm -rf /" "$ALLOW" "$DENY"
expect_deny "env -i" "env -i rm -rf /" "$ALLOW" "$DENY"
expect_deny "env --" "env -- rm -rf /" "$ALLOW" "$DENY"
expect_deny "bash -c" "bash -c 'rm -rf /'" "$ALLOW" "$DENY"
expect_deny "sh -c" "sh -c 'rm -rf /'" "$ALLOW" "$DENY"
expect_deny "bash -lc" "bash -lc 'rm -rf /'" "$ALLOW" "$DENY"
expect_deny "eval" "eval 'rm -rf /'" "$ALLOW" "$DENY"
expect_deny "exec" "exec rm -rf /" "$ALLOW" "$DENY"
expect_deny "trap" "trap 'rm -rf /' EXIT" "$ALLOW" "$DENY"
expect_deny "time" "time rm -rf /" '["Bash(time *)"]' "$DENY"
expect_deny "nohup" "nohup rm -rf /" '["Bash(nohup *)"]' "$DENY"
expect_deny "command" "command rm -rf /" '["Bash(command *)"]' "$DENY"
expect_deny "xargs" "xargs rm -rf /" "$ALLOW" "$DENY"
expect_deny "absolute path" "/bin/rm -rf /" "$ALLOW" '["Bash(rm -rf /)"]'
expect_deny "FOO=bar prefix" "FOO=bar rm -rf /" "$ALLOW" "$DENY"

# ---------------------------------------------------------------------------
echo "=== Nested wrappers ==="

expect_deny "env + bash -c" "env bash -c 'rm -rf /'" "$ALLOW" "$DENY"
expect_deny "command + sh -c" "command sh -c 'rm -rf /'" '["Bash(command *)", "Bash(sh *)", "Bash(rm *)"]' "$DENY"
expect_deny "time + sh -c" "time sh -c 'rm -rf /'" '["Bash(time *)", "Bash(rm *)"]' "$DENY"
expect_deny "env + exec + bash -c" "env exec bash -c 'rm -rf /'" "$ALLOW" "$DENY"
expect_deny "command + command" "command command rm -rf /" '["Bash(command *)"]' "$DENY"
expect_deny "bash -c compound inner" "bash -c 'git status && rm -rf /'" "$ALLOW" "$DENY"
expect_deny "compound + eval" "git status && eval 'rm -rf /'" "$ALLOW" "$DENY"

# ---------------------------------------------------------------------------
echo "=== Deny overrides allow ==="

expect_deny "dd in both allow and deny" \
  "dd if=/dev/zero of=/dev/sda" "$ALLOW" "$DENY"

# ---------------------------------------------------------------------------
print_results

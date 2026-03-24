#!/usr/bin/env bash
# Tests that verify commands ARE auto-approved (allow decision).
# Usage: bash tests/test_allow.sh
#
# Requires: jq, shfmt, bash 4.3+

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/test_helpers.sh"

# ---------------------------------------------------------------------------
echo "=== Simple commands ==="

expect_allow "simple: git status" \
  "git status" '["Bash(git *)"]'

# ---------------------------------------------------------------------------
echo "=== Compound commands ==="

expect_allow "compound: git status && git log" \
  "git status && git log" '["Bash(git *)"]'

# ---------------------------------------------------------------------------
echo "=== Pipes ==="

expect_allow "pipe: git log | head -20" \
  "git log | head -20" '["Bash(git *)", "Bash(head *)"]'

# ---------------------------------------------------------------------------
echo "=== Command substitution ==="

expect_allow 'cmd sub: echo "$(date)"' \
  'echo "$(date)"' '["Bash(echo *)", "Bash(date *)"]'

# ---------------------------------------------------------------------------
echo "=== bash -c recursion ==="

expect_allow "bash -c: inner allowed commands" \
  "bash -c 'git status && git log'" '["Bash(git *)"]'

# ---------------------------------------------------------------------------
echo "=== strip_prefixes: env vars ==="

expect_allow "env var: FOO=bar git status" \
  "FOO=bar git status" '["Bash(git *)"]'
expect_allow 'env var quoted: FOO="hello world" git status' \
  'FOO="hello world" git status' '["Bash(git *)"]'
expect_allow "env var single-quoted: FOO='hello world' git status" \
  "FOO='hello world' git status" '["Bash(git *)"]'
expect_allow "multiple env vars: A=1 B=2 git status" \
  "A=1 B=2 git status" '["Bash(git *)"]'
expect_allow "empty env value: FOO= git status" \
  "FOO= git status" '["Bash(git *)"]'
expect_allow "VAR=val with = in value: A=B=C git status" \
  "A=B=C git status" '["Bash(git *)"]'

# ---------------------------------------------------------------------------
echo "=== Command launchers: env ==="

expect_allow "env launcher: env git status" \
  "env git status" '["Bash(git *)"]'
expect_allow "env launcher: env FOO=bar git status" \
  "env FOO=bar git status" '["Bash(git *)"]'
expect_allow "env launcher: env FOO=bar BAZ=1 git status" \
  "env FOO=bar BAZ=1 git status" '["Bash(git *)"]'
expect_allow "env launcher rule: env git status matches env *" \
  "env git status" '["Bash(env *)"]'

# ---------------------------------------------------------------------------
echo "=== Command launchers: xargs ==="

expect_allow "xargs: xargs -n1 curl" \
  "xargs -n1 curl" '["Bash(curl *)"]'
expect_allow "xargs: xargs -0 -r wc -l" \
  "xargs -0 -r wc -l" '["Bash(wc *)"]'
expect_allow "xargs: xargs -P 4 -n 1 curl" \
  "xargs -P 4 -n 1 curl" '["Bash(curl *)"]'
expect_allow "xargs launcher rule: xargs rm matches xargs *" \
  "xargs rm" '["Bash(xargs *)"]'

# ---------------------------------------------------------------------------
echo "=== Command launchers: bash -c / sh -c ==="

expect_allow "bash -c: inner git matches allow" \
  "bash -c 'git status'" '["Bash(git *)"]'
expect_allow "bash -c inner-only: bash not allowed, inner git matches" \
  "bash -c 'git status'" '["Bash(git *)"]'
expect_allow "bash no -c: bash script.sh matches bash *" \
  "bash script.sh" '["Bash(bash *)"]' '["Bash(rm *)"]'

# ---------------------------------------------------------------------------
echo "=== Combined shell flags ==="

expect_allow "bash -xc: inner matches allow" \
  "bash -xc 'git status'" '["Bash(git *)"]'

# ---------------------------------------------------------------------------
echo "=== Other shells ==="

expect_allow "dash -c: inner matches allow" \
  "dash -c 'git status'" '["Bash(git *)"]'

# ---------------------------------------------------------------------------
echo "=== Command launchers: eval / exec ==="

expect_allow "eval: inner matches allow" \
  "eval 'git status'" '["Bash(git *)"]'

# ---------------------------------------------------------------------------
echo "=== Simple prefix launchers ==="

expect_allow "time -p: flag stripped, inner matches" \
  "time -p git status" '["Bash(time *)", "Bash(git *)"]'
expect_allow "command: inner matches allow" \
  "command git status" '["Bash(git *)"]'

# ---------------------------------------------------------------------------
echo "=== Shell constructs ==="

expect_allow "subshell: (git status && git log)" \
  "(git status && git log)" '["Bash(git *)"]'
expect_allow "if/then: if git status; then echo ok; fi" \
  "if git status; then echo ok; fi" '["Bash(git *)", "Bash(echo *)"]'

# ---------------------------------------------------------------------------
echo "=== Multi-pipe and mixed compound ==="

expect_allow "multi-pipe: git log | grep foo | head -5" \
  "git log | grep foo | head -5" '["Bash(git *)", "Bash(grep *)", "Bash(head *)"]'
expect_allow "mixed pipe+chain: git status | head -5 && echo done" \
  "git status | head -5 && echo done" '["Bash(git *)", "Bash(head *)", "Bash(echo *)"]'

# ---------------------------------------------------------------------------
echo "=== FuncDecl ==="

expect_allow "funcdecl: f() { git status; }; f (body + call allowed)" \
  'f() { git status; }; f' '["Bash(f)", "Bash(git *)"]'

# ---------------------------------------------------------------------------
echo "=== Absolute path normalization ==="

expect_allow "abspath: /opt/homebrew/bin/bash matches bash *" \
  "/opt/homebrew/bin/bash tests/test_hook.sh" '["Bash(bash *)"]'
expect_allow "abspath: /usr/bin/git status matches git *" \
  "/usr/bin/git status" '["Bash(git *)"]'

# ---------------------------------------------------------------------------
echo "=== env flag with safe commands ==="

expect_allow "env -i PATH=/usr/bin git status → allowed" \
  "env -i PATH=/usr/bin git status" \
  '["Bash(env *)", "Bash(bash *)", "Bash(sh *)", "Bash(rm *)", "Bash(git *)"]' \
  '["Bash(rm -rf /)", "Bash(rm -rf ~)", "Bash(chmod 777)"]'

# ---------------------------------------------------------------------------
echo "=== Safety preset: false positive avoidance (should NOT be denied) ==="

SAFETY_DENY='["Bash(rm -rf /)", "Bash(rm -rf ~)", "Bash(chmod 777)", "Bash(chmod -R 777)", "Bash(mkfs *)", "Bash(dd *)", "Bash(git push --force origin main)", "Bash(git push --force origin master)", "Bash(git push -f origin main)", "Bash(git push -f origin master)", "Bash(git reset --hard)"]'
SAFETY_ALLOW='["Bash(rm *)", "Bash(git *)", "Bash(chmod *)", "Bash(echo *)", "Bash(cat *)", "Bash(dd *)"]'

expect_allow "rm -rf /tmp NOT denied by rm -rf / rule" \
  "rm -rf /tmp" '["Bash(git *)", "Bash(rm *)"]' '["Bash(rm -rf /)"]'
expect_allow "rm -rf /* NOT caught by rm -rf / rule (known limitation)" \
  "rm -rf /*" '["Bash(rm *)"]' '["Bash(rm -rf /)"]'
expect_allow "rm -rf ./build NOT denied" \
  "rm -rf ./build" '["Bash(rm *)"]' '["Bash(rm -rf /)"]'
expect_allow "git reset --soft allowed (not matched by --hard rule)" \
  "git reset --soft" '["Bash(git *)"]' '["Bash(git reset --hard)"]'
expect_allow "rm -rf /var/tmp/build allowed" \
  "rm -rf /var/tmp/build" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_allow "rm file.txt allowed" \
  "rm file.txt" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_allow "rm -rf node_modules allowed" \
  "rm -rf node_modules" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_allow "chmod 755 script.sh allowed" \
  "chmod 755 script.sh" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_allow "chmod 644 file.txt allowed" \
  "chmod 644 file.txt" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_allow "chmod +x script.sh allowed" \
  "chmod +x script.sh" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_allow "git push origin main allowed (no --force)" \
  "git push origin main" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_allow "git push --force origin develop allowed (not main/master)" \
  "git push --force origin develop" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_allow "git push -f origin feature/my-branch allowed" \
  "git push -f origin feature/my-branch" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_allow "git push --force-with-lease origin main allowed" \
  "git push --force-with-lease origin main" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_allow "git reset --mixed HEAD~1 allowed" \
  "git reset --mixed HEAD~1" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_allow "git reset HEAD file.txt allowed (no --hard)" \
  "git reset HEAD file.txt" "$SAFETY_ALLOW" "$SAFETY_DENY"

# ---------------------------------------------------------------------------
echo "=== Known limitations (allow is expected) ==="

expect_fallthrough "mkfs.ext4 /dev/sda (period after mkfs, no prefix match)" \
  "mkfs.ext4 /dev/sda" "$SAFETY_ALLOW" "$SAFETY_DENY"
expect_allow "chmod 7777 (extra 7, deny rule chmod 777 doesn't match)" \
  "chmod 7777 file" "$SAFETY_ALLOW" "$SAFETY_DENY"

# ---------------------------------------------------------------------------
echo "=== Harmless wrapper commands ==="

BYPASS_DENY='["Bash(rm -rf /)", "Bash(rm -rf ~)", "Bash(chmod 777)"]'

expect_fallthrough "command -v rm (command stripped, -v rm no match)" \
  "command -v rm" '["Bash(command *)"]' "$BYPASS_DENY"
expect_fallthrough "command --help (command stripped, --help no match)" \
  "command --help" '["Bash(command *)"]' "$BYPASS_DENY"

XARGS_DENY='["Bash(rm -rf /)", "Bash(rm -rf ~)", "Bash(chmod 777)"]'
expect_allow "bare 'xargs' (xargs prefix matches)" \
  "xargs" '["Bash(xargs *)"]' "$XARGS_DENY"

# ---------------------------------------------------------------------------
print_results

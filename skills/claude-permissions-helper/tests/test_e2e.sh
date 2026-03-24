#!/usr/bin/env bash
# End-to-end tests: all Bash presets combined with safety deny list.
#
# Simulates a real user who installed: core + safety + git + go + node +
# python + network + build + devops + github-cli + ruby + rust
#
# Usage: bash tests/test_e2e.sh

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

expect_allow() {
  local name="$1" cmd="$2"
  run_hook "$cmd" "$ALL_ALLOW" "$ALL_DENY"
  local rc=$?
  if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
    pass "$name"
  else
    fail "$name" "exit=$rc output=$RESULT"
  fi
}

expect_deny() {
  local name="$1" cmd="$2"
  run_hook "$cmd" "$ALL_ALLOW" "$ALL_DENY"
  local rc=$?
  if [[ $rc -eq 2 ]] || jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<< "$RESULT" &>/dev/null; then
    pass "$name"
  else
    fail "$name" "exit=$rc output=$RESULT"
  fi
}

expect_fallthrough() {
  local name="$1" cmd="$2"
  run_hook "$cmd" "$ALL_ALLOW" "$ALL_DENY"
  local rc=$?
  if [[ $rc -eq 0 ]] && { [[ -z "$RESULT" ]] || ! jq -e '.hookSpecificOutput.permissionDecision' <<< "$RESULT" &>/dev/null; }; then
    pass "$name"
  else
    fail "$name" "exit=$rc output=$RESULT"
  fi
}

expect_not_approved() {
  local name="$1" cmd="$2"
  run_hook "$cmd" "$ALL_ALLOW" "$ALL_DENY"
  local rc=$?
  if [[ $rc -eq 0 ]] && jq -e '.hookSpecificOutput.permissionDecision == "allow"' <<< "$RESULT" &>/dev/null; then
    fail "$name → AUTO-APPROVED" "should not be approved"
  else
    pass "$name"
  fi
}

# ---------------------------------------------------------------------------
# Build combined allow list from all Bash presets (excluding MCP/readonly)
# ---------------------------------------------------------------------------
ALL_ALLOW=$(jq -n '[
  "Bash(mkdir *)", "Bash(cd *)", "Bash(ls *)", "Bash(cat *)", "Bash(touch *)",
  "Bash(cp *)", "Bash(mv *)", "Bash(pwd *)", "Bash(echo *)", "Bash(test *)",
  "Bash(read *)", "Bash(break *)", "Bash(continue *)", "Bash(exit *)",
  "Bash(return *)", "Bash(rev *)", "Bash(exec *)", "Bash(export *)",
  "Bash(local *)", "Bash(declare *)", "Bash(unset *)", "Bash(set *)",
  "Bash(shift *)", "Bash(trap *)", "Bash(printf *)", "Bash(grep *)",
  "Bash(egrep *)", "Bash(fgrep *)", "Bash(find *)", "Bash(which *)",
  "Bash(whereis *)", "Bash(whoami *)", "Bash(date *)", "Bash(printenv *)",
  "Bash(head *)", "Bash(tail *)", "Bash(less *)", "Bash(more *)",
  "Bash(wc *)", "Bash(sort *)", "Bash(uniq *)", "Bash(cut *)", "Bash(tr *)",
  "Bash([ *)", "Bash(tee *)", "Bash(basename *)", "Bash(dirname *)",
  "Bash(realpath *)", "Bash(readlink *)", "Bash(mkfifo *)", "Bash(mktemp *)",
  "Bash(seq *)", "Bash(true *)", "Bash(false *)", "Bash(sleep *)",
  "Bash(column *)", "Bash(paste *)", "Bash(nl *)", "Bash(tput *)",
  "Bash(bc *)", "Bash(expr *)", "Bash(base64 *)", "Bash(shasum *)",
  "Bash(md5 *)", "Bash(sed *)", "Bash(awk *)", "Bash(comm *)", "Bash(fold *)",
  "Bash(diff *)", "Bash(cmp *)", "Bash(file *)", "Bash(stat *)", "Bash(du *)",
  "Bash(df *)", "Bash(ps *)", "Bash(top *)", "Bash(htop *)", "Bash(uname *)",
  "Bash(hostname *)", "Bash(uptime *)", "Bash(history *)", "Bash(tar *)",
  "Bash(gzip *)", "Bash(gunzip *)", "Bash(zip *)", "Bash(unzip *)",
  "Bash(tree *)", "Bash(jq *)", "Bash(yq *)", "Bash(lsof *)", "Bash(pgrep *)",
  "Bash(wait *)",

  "Bash(git add *)", "Bash(git status *)", "Bash(git diff *)",
  "Bash(git log *)", "Bash(git commit *)", "Bash(git branch *)",
  "Bash(git checkout *)", "Bash(git switch *)", "Bash(git merge *)",
  "Bash(git rebase *)", "Bash(git pull *)", "Bash(git push *)",
  "Bash(git fetch *)", "Bash(git stash *)", "Bash(git show *)",
  "Bash(git blame *)", "Bash(git tag *)", "Bash(git cherry-pick *)",
  "Bash(git reset *)", "Bash(git restore *)", "Bash(git clean *)",
  "Bash(git remote *)", "Bash(git submodule *)", "Bash(git ls-files *)",
  "Bash(git ls-tree *)", "Bash(git rev-parse *)", "Bash(git config *)",
  "Bash(git clone *)", "Bash(git init *)",

  "Bash(go *)", "Bash(golangci-lint *)", "Bash(goimports *)", "Bash(gofmt *)",

  "Bash(npm *)", "Bash(yarn *)", "Bash(pnpm *)", "Bash(bun *)",
  "Bash(node *)", "Bash(deno *)", "Bash(jest *)", "Bash(vitest *)",

  "Bash(python *)", "Bash(python3 *)", "Bash(pip *)", "Bash(pip3 *)",
  "Bash(poetry *)", "Bash(uv *)", "Bash(pytest *)", "Bash(black *)",
  "Bash(ruff *)", "Bash(mypy *)", "Bash(pylint *)", "Bash(flake8 *)",
  "Bash(isort *)", "Bash(coverage *)", "Bash(pydoc *)",

  "Bash(curl *)", "Bash(wget *)", "Bash(ssh *)", "Bash(scp *)", "Bash(rsync *)",

  "Bash(make *)", "Bash(cmake *)", "Bash(gradle *)", "Bash(mvn *)", "Bash(shfmt *)",

  "Bash(docker *)", "Bash(docker-compose *)", "Bash(kubectl *)",
  "Bash(terraform *)", "Bash(aws *)", "Bash(gcloud *)", "Bash(az *)",
  "Bash(heroku *)", "Bash(netlify *)", "Bash(vercel *)",

  "Bash(gh *)",

  "Bash(ruby *)", "Bash(bundle *)", "Bash(gem *)", "Bash(rake *)",
  "Bash(rails *)", "Bash(rspec *)", "Bash(rubocop *)",

  "Bash(cargo *)", "Bash(rustc *)", "Bash(rustup *)", "Bash(clippy *)",
  "Bash(rustfmt *)",

  "Bash(gws *)"
]')

ALL_DENY=$(jq -n '[
  "Bash(rm -rf /)", "Bash(rm -rf ~)",
  "Bash(chmod 777)", "Bash(chmod -R 777)",
  "Bash(mkfs *)", "Bash(dd *)",
  "Bash(git push --force origin main)", "Bash(git push --force origin master)",
  "Bash(git push -f origin main)", "Bash(git push -f origin master)",
  "Bash(git reset --hard)"
]')

# ===========================================================================
echo "=== Core: simple commands ==="

expect_allow "ls -la" "ls -la"
expect_allow "cat file.txt" "cat file.txt"
expect_allow "echo hello" "echo hello"
expect_allow "grep -r pattern ." "grep -r pattern ."
expect_allow "find . -name '*.go'" "find . -name '*.go'"
expect_allow "head -20 file" "head -20 file"
expect_allow "wc -l file" "wc -l file"
expect_allow "jq '.key' file.json" "jq '.key' file.json"
expect_allow "sed 's/old/new/g' file" "sed 's/old/new/g' file"
expect_allow "diff file1 file2" "diff file1 file2"
expect_allow "tar xzf archive.tar.gz" "tar xzf archive.tar.gz"

# ===========================================================================
echo "=== Core: compound commands ==="

expect_allow "ls && echo done" "ls && echo done"
expect_allow "grep foo file | head -5" "grep foo file | head -5"
expect_allow "find . -name '*.go' | wc -l" "find . -name '*.go' | wc -l"
expect_allow "cat file | sort | uniq -c | sort -rn | head" \
  "cat file | sort | uniq -c | sort -rn | head"
expect_allow "mkdir -p dir && touch dir/file" "mkdir -p dir && touch dir/file"
expect_allow "ls -la; echo done" "ls -la; echo done"

# ===========================================================================
echo "=== Core: env var prefixes ==="

expect_allow "FOO=bar echo hello" "FOO=bar echo hello"
expect_allow "GOPATH=/tmp go version" "GOPATH=/tmp go version"
expect_allow "NODE_ENV=test npm test" "NODE_ENV=test npm test"
expect_allow "env git status (stripped to git)" "env git status"

# ===========================================================================
echo "=== Git: common workflows ==="

expect_allow "git status" "git status"
expect_allow "git diff" "git diff"
expect_allow "git log --oneline -10" "git log --oneline -10"
expect_allow "git add file.go" "git add file.go"
expect_allow "git commit -m 'fix bug'" "git commit -m 'fix bug'"
expect_allow "git push origin feature" "git push origin feature"
expect_allow "git pull --rebase" "git pull --rebase"
expect_allow "git stash && git checkout main" "git stash && git checkout main"
expect_allow "git diff | head -50" "git diff | head -50"
expect_allow "git log --oneline | grep fix" "git log --oneline | grep fix"
expect_allow "git branch -a" "git branch -a"
expect_allow "git reset --soft HEAD~1" "git reset --soft HEAD~1"
expect_allow "git push --force origin feature/my-branch" \
  "git push --force origin feature/my-branch"

# ===========================================================================
echo "=== Go: build & test ==="

expect_allow "go build ./..." "go build ./..."
expect_allow "go test ./..." "go test ./..."
expect_allow "go test -v -run TestFoo ./pkg/..." "go test -v -run TestFoo ./pkg/..."
expect_allow "go mod tidy" "go mod tidy"
expect_allow "golangci-lint run" "golangci-lint run"
expect_allow "go build ./... && go test ./..." "go build ./... && go test ./..."

# ===========================================================================
echo "=== Node: build & test ==="

expect_allow "npm install" "npm install"
expect_allow "npm test" "npm test"
expect_allow "npm run build" "npm run build"
expect_allow "yarn test" "yarn test"
expect_allow "pnpm install" "pnpm install"
expect_allow "bun test" "bun test"
expect_allow "jest --coverage" "jest --coverage"
expect_allow "npm install && npm test" "npm install && npm test"

# ===========================================================================
echo "=== Python: build & test ==="

expect_allow "python3 -m pytest" "python3 -m pytest"
expect_allow "pip install -r requirements.txt" "pip install -r requirements.txt"
expect_allow "pytest -v tests/" "pytest -v tests/"
expect_allow "black ." "black ."
expect_allow "ruff check ." "ruff check ."
expect_allow "mypy src/" "mypy src/"
expect_allow "python3 script.py" "python3 script.py"

# ===========================================================================
echo "=== Network tools ==="

expect_allow "curl -s https://api.example.com" "curl -s https://api.example.com"
expect_allow "wget -q file.txt" "wget -q file.txt"
expect_allow "curl -s url | jq '.data'" "curl -s url | jq '.data'"

# ===========================================================================
echo "=== Build & DevOps ==="

expect_allow "make build" "make build"
expect_allow "docker build -t myapp ." "docker build -t myapp ."
expect_allow "docker-compose up -d" "docker-compose up -d"
expect_allow "kubectl get pods" "kubectl get pods"
expect_allow "terraform plan" "terraform plan"
expect_allow "make test && make build" "make test && make build"

# ===========================================================================
echo "=== GitHub CLI ==="

expect_allow "gh pr list" "gh pr list"
expect_allow "gh pr create --title 'fix'" "gh pr create --title 'fix'"
expect_allow "gh issue list | head -10" "gh issue list | head -10"

# ===========================================================================
echo "=== Ruby & Rust ==="

expect_allow "bundle install" "bundle install"
expect_allow "rspec spec/" "rspec spec/"
expect_allow "cargo build" "cargo build"
expect_allow "cargo test" "cargo test"

# ===========================================================================
echo "=== GWS ==="

expect_allow "gws docs cat docid" "gws docs cat docid"

# ===========================================================================
echo "=== Safety: deny list blocks dangerous commands ==="

expect_deny "rm -rf /" "rm -rf /"
expect_deny "rm -rf ~" "rm -rf ~"
expect_deny "rm -rf ~/Documents" "rm -rf ~/Documents"
expect_deny "chmod 777 /etc/passwd" "chmod 777 /etc/passwd"
expect_deny "chmod -R 777 /var" "chmod -R 777 /var"
expect_deny "dd if=/dev/zero of=/dev/sda" "dd if=/dev/zero of=/dev/sda"
expect_deny "mkfs /dev/sda" "mkfs /dev/sda"
expect_deny "git push --force origin main" "git push --force origin main"
expect_deny "git push --force origin master" "git push --force origin master"
expect_deny "git push -f origin main" "git push -f origin main"
expect_deny "git push -f origin master" "git push -f origin master"
expect_deny "git reset --hard" "git reset --hard"
expect_deny "git reset --hard HEAD~3" "git reset --hard HEAD~3"

# ===========================================================================
echo "=== Safety: deny wins even in compounds ==="

expect_deny "echo ok && rm -rf /" "echo ok && rm -rf /"
expect_deny "git status; git reset --hard" "git status; git reset --hard"
expect_deny "ls | dd if=/dev/zero of=/dev/sda" "ls | dd if=/dev/zero of=/dev/sda"
expect_deny "FOO=bar rm -rf /" "FOO=bar rm -rf /"
expect_deny "env rm -rf /" "env rm -rf /"
expect_deny "(rm -rf /)" "(rm -rf /)"
expect_deny 'echo "$(rm -rf /)"' 'echo "$(rm -rf /)"'
expect_deny "bash -c 'rm -rf /'" "bash -c 'rm -rf /'"
expect_deny "eval 'git reset --hard'" "eval 'git reset --hard'"

# ===========================================================================
echo "=== Safety: safe variants NOT denied ==="

expect_not_approved "rm -rf node_modules (rm not in any preset)" "rm -rf node_modules"
expect_not_approved "rm -rf /tmp/build (rm not in any preset)" "rm -rf /tmp/build"
expect_not_approved "rm file.txt (rm not in any preset)" "rm file.txt"
expect_not_approved "chmod 755 script.sh (chmod not in any preset)" "chmod 755 script.sh"
expect_not_approved "chmod +x script.sh (chmod not in any preset)" "chmod +x script.sh"
expect_allow "git push origin main (no --force)" "git push origin main"
expect_allow "git push --force origin develop" "git push --force origin develop"
expect_allow "git push --force-with-lease origin main" \
  "git push --force-with-lease origin main"
expect_allow "git reset --soft HEAD~1" "git reset --soft HEAD~1"
expect_allow "git reset HEAD file.txt" "git reset HEAD file.txt"

# ===========================================================================
echo "=== Wrapper stripping: no wrappers in allow list ==="

expect_allow "bash -c 'curl ...' (curl in network preset, inner allowed)" \
  "bash -c 'curl http://example.com'"
expect_allow "sh -c 'pip install pkg' (pip in python preset, inner allowed)" \
  "sh -c 'pip install requests'"
expect_not_approved "bash -c 'nc -l 4444' (nc not in any preset)" \
  "bash -c 'nc -l 4444'"
expect_not_approved "sh -c 'crontab -e' (crontab not in any preset)" \
  "sh -c 'crontab -e'"
expect_allow "bash -c 'git status' (inner git allowed via stripping)" \
  "bash -c 'git status'"
expect_allow "env go test ./... (env stripped, go allowed)" \
  "env go test ./..."
expect_allow "exec npm test (exec stripped, npm allowed)" \
  "exec npm test"

# ===========================================================================
echo "=== Real-world compound workflows ==="

expect_allow "go test && golangci-lint run" \
  "go test ./... && golangci-lint run"
expect_allow "npm install && npm run build && npm test" \
  "npm install && npm run build && npm test"
expect_allow "git stash && git pull --rebase && git stash pop" \
  "git stash && git pull --rebase && git stash pop"
expect_allow "docker build -t app . && docker run app" \
  "docker build -t app . && docker run app"
expect_allow "find . -name '*.go' | grep -v vendor | wc -l" \
  "find . -name '*.go' | grep -v vendor | wc -l"
expect_allow "git diff --stat | tail -1" \
  "git diff --stat | tail -1"
expect_allow "kubectl get pods | grep Error" \
  "kubectl get pods | grep Error"
expect_allow "cargo test 2>&1 | head -50" \
  "cargo test 2>&1 | head -50"
expect_allow "pytest -v 2>&1 | tail -20" \
  "pytest -v 2>&1 | tail -20"
expect_allow "gh pr list | grep my-branch" \
  "gh pr list | grep my-branch"

# ===========================================================================
echo "=== Cross-preset interaction: deny overrides allow ==="

expect_deny "dd (in both core and safety deny)" \
  "dd if=/dev/zero of=/dev/sda bs=1M"
expect_deny "git reset --hard (git allow + safety deny)" \
  "git reset --hard origin/main"
expect_deny "git push -f origin main (git allow + safety deny)" \
  "git push -f origin main"
expect_deny "mkfs /dev/sda (safety deny)" \
  "mkfs /dev/sda"

# ===========================================================================
echo "=== Commands NOT in any preset ==="

expect_not_approved "systemctl restart (not in any preset)" \
  "systemctl restart nginx"
expect_not_approved "useradd (not in any preset)" \
  "useradd -m hacker"
expect_not_approved "crontab (not in any preset)" \
  "crontab -e"
expect_not_approved "nc (netcat, not in any preset)" \
  "nc -l 4444"
expect_not_approved "nmap (not in any preset)" \
  "nmap -sS 10.0.0.1"

# ---------------------------------------------------------------------------
echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1

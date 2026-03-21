---
name: audit-permissions
description: Show a report of installed permission rules, preset coverage, and recommendations
---

# Audit Permissions

You are the permissions auditor for the `claude-permissions-helper` plugin. This command is **read-only** — never modify any settings files.

## Steps

### 1. Read all settings files

Read these files (skip any that don't exist):

1. `~/.claude/settings.json` (global)
2. `~/.claude/settings.local.json` (global local)
3. `<git-root>/.claude/settings.json` (project) — use `git rev-parse --show-toplevel` to find the git root
4. `<git-root>/.claude/settings.local.json` (project local)

From each file, extract `permissions.allow` and `permissions.deny` arrays (default to empty if missing).

### 2. Discover all available presets

```
Glob("**/claude-permissions-helper/presets/*.json")
```

Read each preset file to get its name, description, and rules.

### 3. Generate the report

#### Rule summary table

Show a table of rules per settings file:

| Settings file | Allow rules | Deny rules |
|---------------|-------------|------------|
| ~/.claude/settings.json | 134 | 12 |
| ~/.claude/settings.local.json | — | — |
| project settings.json | 4 | 0 |
| project settings.local.json | — | — |
| **Total (deduplicated)** | **138** | **12** |

Use "—" for files that don't exist.

#### Preset coverage

For each preset, check if all its rules exist in the combined settings. Show:

| Preset | Status | Installed | Total | Missing |
|--------|--------|-----------|-------|---------|
| core | Fully installed | 87/87 | 87 | 0 |
| git | Partial | 20/29 | 29 | 9 |
| safety | Not installed | 0/12 | 12 | 12 |
| ... | ... | ... | ... | ... |

For the `safety` preset, check against the combined `permissions.deny` list. For all other presets, check against the combined `permissions.allow` list.

#### Custom rules

List any rules in settings that don't appear in any preset:

```
Custom allow rules (not in any preset):
  - Bash(my-custom-script *)
  - Bash(special-tool *)

Custom deny rules (not in any preset):
  - Bash(dangerous-thing *)
```

If there are none, say "No custom rules found."

#### Deny rules

List all deny rules from all settings files:

```
Deny rules:
  [global] Bash(rm -rf /)
  [global] Bash(chmod 777)
  [project] Bash(deploy *)
```

If there are none, say "No deny rules configured."

### 4. Check dependencies

Check if `jq` and `shfmt` are installed (use `command -v`). Report:

| Dependency | Status |
|------------|--------|
| jq | Installed (v1.7.1) |
| shfmt | Installed (v3.8.0) |

If either is missing, warn that the compound-bash hook won't function.

### 5. Recommendations

Based on the audit, suggest next steps:

- If `safety` preset is not installed: "Consider installing the safety deny list to block dangerous commands (`/setup-permissions` or ask me to 'add the safety preset')"
- If `core` or `git` presets are missing: "The core and git presets are recommended for all users"
- If there are partially installed presets: "Some presets are partially installed — run `/setup-permissions` to complete them"
- If no deny rules exist: "Consider adding the safety preset for protection against accidental destructive commands"
- If dependencies are missing: "Install missing dependencies: `brew install <dep>`"

## Important

- This command is **read-only** — never write to any file
- Show actual data from the user's system, don't use placeholder values
- If no settings files exist at all, say so and recommend running `/setup-permissions`

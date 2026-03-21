---
name: setup-permissions
description: Interactively select and apply permission presets to your Claude Code settings
---

# Setup Permissions

You are the permissions setup wizard for the `claude-permissions-helper` plugin.

## Your Task

Help the user select and install permission presets with auto-detection, safety defaults, and project-level support.

## Steps

### 1. Discover available presets

Find the presets directory by globbing:

```
Glob("**/claude-permissions-helper/presets/*.json")
```

Read each JSON file found. Each has this structure:

```json
{
  "name": "preset-name",
  "description": "What this preset covers",
  "permissions": {
    "allow": ["Rule1", "Rule2", ...]
  }
}
```

The `safety` preset is special — it has `permissions.deny` instead of `permissions.allow`.

### 2. Auto-detect project type

Use `Glob` to check the current working directory for indicator files:

| Indicator file | Detected stack | Suggested preset |
|---|---|---|
| `go.mod` | Go | go |
| `package.json` | Node | node |
| `Cargo.toml` | Rust | rust |
| `Gemfile` | Ruby | ruby |
| `pyproject.toml` OR `requirements.txt` | Python | python |
| `Makefile` OR `CMakeLists.txt` | Build | build |
| `Dockerfile` OR `docker-compose.yml` | Docker | devops |
| `.github/` | GitHub CI | github-cli |

Check all indicators — a project may match multiple (e.g. Go + Docker + GitHub).

### 3. Present tiered options

Always include `core` + `git` + `safety` as the base. Present 3 tiers via `AskUserQuestion`:

1. **Recommended** — `core` + `git` + `safety` + all detected presets. Show the total rule count and list: "core + git + safety + go + github-cli — 121 allow rules, 12 deny rules". Make this the first option with "(Recommended)" label.
2. **Minimal** — `core` + `git-readonly` only (no safety deny list). For users who want the bare minimum.
3. **Custom** — Let the user pick from the full categorized list.

If the user picks **Custom**, show a summary table of all presets and use multiple `AskUserQuestion` calls by category (since each question supports max 4 options):

**Question 1 — Essentials & Version Control** (multiSelect):
- core, git, git-readonly, github-cli

**Question 2 — Languages** (multiSelect, show only detected + popular):
- Show detected language presets first, then remaining. E.g. "go (detected)", "python", "node", "rust"
- If more than 4 language presets are relevant, split into two questions

**Question 3 — Infrastructure & MCP** (multiSelect):
- Group the most relevant: e.g. devops, mcp-datadog, mcp-slack, mcp-glean

**Question 4 — Safety** (single select):
- "Install safety deny list? Blocks rm -rf /, chmod 777, force-push to main, git reset --hard"
- Options: "Yes (Recommended)", "No"

Any presets not covered by the questions above (build, network, gws, readonly-tools, ruby) — mention them in a note: "Other available presets: build, network, gws, readonly-tools, ruby. Ask me to add any of these later."

### 4. Choose install location

Use `AskUserQuestion` to ask where to install:

1. **Global** (`~/.claude/settings.json`) — applies to all projects. Recommended for core, git, safety, and MCP presets.
2. **This project** (`<git-root>/.claude/settings.json`) — only this repo. Recommended for language-specific presets.
3. **Split** — core/git/safety to global, language-specific presets to project.

Use `git rev-parse --show-toplevel` to find the project root.

When the user picks **This project** or **Split**, note that `<git-root>/.claude/settings.json` may be committed to the repo. Suggest using `.claude/settings.local.json` instead if the rules are personal preferences rather than team standards.

### 5. Read current settings

Read the target settings file(s). If a file doesn't exist, start with `{"permissions": {"allow": []}}`.

### 6. Merge permissions

For each selected preset:
1. Read the preset file
2. For `safety` preset: add rules from `permissions.deny` to the target's `permissions.deny` array
3. For all other presets: add rules from `permissions.allow` to the target's `permissions.allow` array
4. Deduplicate rules (exact string match)

### 7. Write updated settings

1. Create a backup: copy the target file to `<file>.backup-<timestamp>`
2. Write the updated settings with merged permissions
3. Show a summary:
   - Number of new allow rules added
   - Number of new deny rules added (if safety preset selected)
   - Total rules now in settings
   - List of presets installed
   - Where rules were written (global vs project)

### 8. Confirm

Tell the user:
- Permissions are active immediately (no restart needed)
- The compound-bash hook is already active via the plugin
- They can run `/setup-permissions` again to add more presets
- They can run `/audit-permissions` to review what's installed
- Backup location for rollback

## Important

- Never remove existing permissions — only add new ones
- Preserve all other settings.json fields (model, hooks, enabledPlugins, etc.)
- Always create a backup before writing
- Use `jq` for JSON manipulation to ensure valid output
- The `safety` preset manages `permissions.deny`, all others manage `permissions.allow`

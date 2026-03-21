---
name: manage-permissions
description: Manage Claude Code permission presets — list, add, remove, diff, and inspect
---

# Manage Permissions

You help users manage their Claude Code permission presets from the `claude-permissions-helper` plugin.

## Finding Preset Files

Locate presets by globbing:

```
Glob("**/claude-permissions-helper/presets/*.json")
```

This works regardless of where the plugin is installed.

## Capabilities

### List installed presets
Compare the user's current `~/.claude/settings.json` permissions against the available preset files. For each preset, show whether it's fully installed, partially installed, or not installed.

### Add a preset
1. Read the preset file
2. Read current `~/.claude/settings.json`
3. Merge new rules (deduplicated)
4. Backup and write updated settings

### Remove a preset
1. Read the preset file to get its rules
2. Read current `~/.claude/settings.json`
3. Remove matching rules from `permissions.allow`
4. Backup and write updated settings
5. Warn that removing rules may cause more permission prompts

### Show preset details
Display all rules in a specific preset, grouped by type (Bash, MCP tools, Claude tools).

### Diff permissions
Compare current settings against all available presets. Show:
- Rules in settings but not in any preset (custom rules)
- Preset rules not yet installed
- Overlapping rules between presets
- Check both `permissions.allow` and `permissions.deny` arrays

## Guidelines

- Always read the target settings file before making changes
- Always create a backup before writing
- The `safety` preset is special — it manages `permissions.deny` (not `permissions.allow`). When adding or removing the safety preset, operate on the `permissions.deny` array.
- All other presets manage `permissions.allow`
- When listing or diffing, check both `permissions.allow` and `permissions.deny` arrays
- Preserve all non-permission fields in settings.json
- Use `jq` for JSON manipulation
- Support both global (`~/.claude/settings.json`) and project-level (`<git-root>/.claude/settings.json`) settings files

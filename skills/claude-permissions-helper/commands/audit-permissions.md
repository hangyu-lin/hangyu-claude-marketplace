---
name: audit-permissions
description: Audit installed permissions, or diagnose why a specific command was denied
---

# Audit Permissions

You are the permissions auditor for the `claude-permissions-helper` plugin.

## Mode Detection

Check whether the user provided a command argument after `/audit-permissions`:

- **No argument** → run [Full Audit Mode](#full-audit-mode)
- **Argument provided** (e.g. `/audit-permissions comm -13 <(git show ...)`) → run [Diagnose Mode](#diagnose-mode)

If the argument looks like a pasted error message (e.g. contains "permission denied" or "not allowed"), extract the actual command from within it and use that.

---

## Full Audit Mode

This mode is **read-only** — never modify any settings files.

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

---

## Diagnose Mode

This mode diagnoses why a specific command triggered a permission prompt and offers to fix it.

### Step 1: Extract the command

Take everything after `/audit-permissions` as the command to diagnose. If the user pasted an error message or prompt text, extract the actual shell command from within it.

### Step 2: Decompose compound commands

Check if the command contains shell metacharacters (`|`, `&&`, `||`, `;`, `<(`, `>(`, `` ` ``, `$(`, newlines):

**If compound** — use the hook's parse mode to decompose it:

```bash
echo "<command>" | bash <plugin-root>/hooks/approve-compound-bash.sh parse
```

Find `<plugin-root>` by globbing:
```
Glob("**/claude-permissions-helper/hooks/approve-compound-bash.sh")
```

Collect the output lines — each is a sub-command. Extract the unique root binary (first word) from each.

**If shfmt is not available** — fall back to heuristic parsing: split the command on `|`, `&&`, `||`, `;` and take the first word of each segment. Note in the output that parsing was approximate.

**If simple** — just extract the root binary (first word of the command).

### Step 3: Read settings + presets

Same as Full Audit steps 1-2:

1. Read all 4 settings files (global, global local, project, project local)
2. Glob and read all preset files

Combine all `permissions.allow` and `permissions.deny` rules across settings files (deduplicated).

### Step 4: Check each binary

For each unique root binary extracted in Step 2, determine:

1. **Allowed?** — Is `Bash(<binary> *)` in any settings file's `permissions.allow`? If so, which file?
2. **Denied?** — Is it in any `permissions.deny`? If so, which file?
3. **In a preset?** — Does `Bash(<binary> *)` appear in any preset file? If so, which preset(s)?
4. **Installed on system?** — Run `command -v <binary>` to check. If found, note the path.

### Step 5: Report

Output a concise diagnosis:

```
## Permission Diagnosis: `<original command>`
```

If compound, show the sub-command breakdown:

```
### Sub-commands
| Sub-command | Binary | Status |
|---|---|---|
| comm -13 ... | comm | NOT ALLOWED |
| git show HEAD~2:file | git | Allowed (global settings) |
| sort | sort | Allowed (core preset → global settings) |
```

For each binary that is NOT currently allowed, show a detailed section:

```
### Missing: `comm`
- Risk: LOW — read-only text comparison utility, cannot modify files
- Not in any settings file
- Not in any preset
- Installed at /usr/bin/comm
- Suggested preset: `core` (text processing tools)
```

For non-Bash tool rules (Read, Glob, Edit, etc.), check the `readonly-tools` preset.

### Step 6: Risk assessment

Before offering fixes, classify each missing binary's risk level:

**Low risk** (read-only / text processing) — tools that cannot modify files or make network calls:
`comm`, `sort`, `wc`, `head`, `tail`, `rev`, `paste`, `fold`, `nl`, `column`, `tee`, `cat`, `less`, `more`, `diff`, `cmp`, `file`, `stat`, `du`, `df`, `seq`, `bc`, `expr`, `base64`, `shasum`, `md5`, `basename`, `dirname`, `realpath`, `readlink`, `uname`, `hostname`, `uptime`, `whoami`, `date`, `printenv`, `which`, `whereis`, `true`, `false`, `printf`, `echo`, `test`, `[`, etc.
→ Safe to auto-allow. These cannot modify files or make network calls.

**Medium risk** (file modification / system inspection):
`patch`, `install`, `rsync`, `find`, `xargs`, `tar`, `gzip`, `zip`, `sed`, `awk`, `tee`, `mktemp`, `cp`, `mv`, `touch`, `mkdir`, etc.
→ Allow with caution. Note what the tool can do (e.g., "rsync can transfer files to remote hosts").

**High risk** (destructive / network / privileged):
`rm`, `chmod`, `chown`, `curl`, `wget`, `nc`, `nmap`, `docker`, `kubectl`, `ssh`, `scp`, `sudo`, `su`, `kill`, `pkill`, `dd`, `mount`, `umount`, etc.
→ Warn explicitly. Explain the blast radius (e.g., "`curl` can exfiltrate data to external endpoints").

Use your knowledge to classify binaries not in the above lists. When uncertain, default to medium risk.

Display the risk in the report for each missing binary:

```
### Missing: `comm`
- Risk: LOW — read-only text comparison utility, cannot modify files
- Not in any settings file or preset
- Installed at /usr/bin/comm
```

```
### Missing: `rsync`
- Risk: MEDIUM — can copy/sync files locally and to remote hosts
- Found in preset: `network`
- Not in your settings
```

```
### Missing: `docker`
- Risk: HIGH — can run arbitrary containers, mount host filesystem, access network
- Found in preset: `devops`
- Not in your settings
```

### Step 7: Offer fix

Use `AskUserQuestion` to offer to add the missing rules. Options vary by risk level:

**Low risk binaries:**
1. "Add `Bash(<binary> *)` to global settings (Recommended)" — first option, marked recommended
2. "Add to project settings"
3. "Skip"

**Medium risk binaries:**
1. "Add `Bash(<binary> *)` to global settings" — description notes the risk
2. "Add to project settings"
3. "Skip"

**High risk binaries:**
- Do NOT offer `AskUserQuestion` options to add high-risk binaries. Instead, report the risk and tell the user: "This is a high-risk command. If you want to allow it, tell me explicitly (e.g. 'add rm to global settings') and I'll do it with a warning."
- Never present a one-click option for high-risk tools — the user must make a deliberate, explicit request.

If multiple binaries need fixing, batch them into one `AskUserQuestion` where practical, grouping by risk level. If there are more than 4 missing binaries, use multiple questions.

**Applying the fix:**

If the user chooses to add a rule:

1. Read the target settings file (`~/.claude/settings.json` for global, `<git-root>/.claude/settings.json` for project)
2. Create a backup: copy to `<file>.backup-<timestamp>`
3. Use `jq` to append the new rule(s) to `permissions.allow` and deduplicate:
   ```bash
   jq '.permissions.allow = (.permissions.allow + ["Bash(<binary> *)"] | unique)' <file> > tmp && mv tmp <file>
   ```
4. Confirm what was added, restate the risk level

### Edge Cases

- **Binary is in a deny list** → warn the user that it's explicitly denied, explain which settings file denies it, and do NOT offer to auto-add it. Suggest they review and manually remove the deny rule if intended.
- **Binary not installed on system** → note "not found on this system" and suggest installation (e.g., `brew install <binary>`) before adding the permission rule.
- **Already allowed** → report it as allowed, show which settings file or preset covers it. No fix needed.
- **Non-Bash tools** (Read, Glob, Edit, Write, etc.) → if the denied tool isn't a Bash command, check the `readonly-tools` preset and suggest it if relevant.
- **shfmt unavailable** → use the heuristic fallback for compound parsing (split on `|`, `&&`, `||`, `;`). Note the approximation.
- **No missing binaries** → all sub-commands are already allowed. Report this clearly: "All commands in this pipeline are already allowed. The permission prompt may have been triggered by a different mechanism."

## Important

- In **Full Audit Mode**: this command is **read-only** — never write to any file
- In **Diagnose Mode**: only write to settings files if the user explicitly approves the fix via `AskUserQuestion`
- Show actual data from the user's system, don't use placeholder values
- If no settings files exist at all, say so and recommend running `/setup-permissions`

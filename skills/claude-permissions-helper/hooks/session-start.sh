#!/usr/bin/env bash
# SessionStart hook for claude-permissions-helper plugin.
# Shows a one-time welcome nudge when no Bash permission rules are configured.
# Silent on subsequent sessions or when rules already exist.

set -euo pipefail

CONFIG_DIR="${HOME}/.config/claude-permissions-helper"
WELCOMED_FLAG="${CONFIG_DIR}/.welcomed"

# Already shown — exit silently
[ -f "${WELCOMED_FLAG}" ] && exit 0

# Check for Bash allow rules in global settings
HAS_BASH_RULES=false
SETTINGS="${HOME}/.claude/settings.json"
if [ -f "${SETTINGS}" ] && command -v jq &>/dev/null; then
  count=$(jq '[.permissions.allow[]? // empty | select(startswith("Bash("))] | length' "${SETTINGS}" 2>/dev/null || echo "0")
  [ "${count}" -gt 0 ] && HAS_BASH_RULES=true
fi

# User already has rules — mark welcomed, exit silently
if ${HAS_BASH_RULES}; then
  mkdir -p "${CONFIG_DIR}" && touch "${WELCOMED_FLAG}"
  exit 0
fi

# First run, no rules — show welcome
mkdir -p "${CONFIG_DIR}" && touch "${WELCOMED_FLAG}"

escape_for_json() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

# Check for missing dependencies
MISSING_DEPS=""
command -v jq &>/dev/null || MISSING_DEPS="jq"
command -v shfmt &>/dev/null || MISSING_DEPS="${MISSING_DEPS:+${MISSING_DEPS}, }shfmt"

MSG="claude-permissions-helper: No Bash permission rules configured yet — the hook can't auto-approve commands. Run /setup-permissions to set up presets for your stack, or say 'add the core and git presets' for quick defaults."
if [ -n "${MISSING_DEPS}" ]; then
  MSG="${MSG} WARNING: Missing dependencies (${MISSING_DEPS}) — install with: brew install ${MISSING_DEPS// /}"
fi
escaped=$(escape_for_json "${MSG}")

cat <<EOF
{
  "additional_context": "${escaped}",
  "hookSpecificOutput": {
    "hookEventName": "SessionStart",
    "additionalContext": "${escaped}"
  }
}
EOF

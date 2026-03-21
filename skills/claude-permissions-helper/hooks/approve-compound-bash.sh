#!/usr/bin/env bash
# shellcheck shell=bash
# approve-compound-bash — PreToolUse hook for Claude Code
# Version: 1.0.0 (claude-permissions-helper plugin)
#
# Auto-approves compound Bash commands (pipes, chains, subshells, etc.)
# when every sub-command matches your allow list and none match your deny
# list. Actively denies compounds containing denied segments. Falls
# through on unknown commands for Claude Code's native prompt.
#
# Dependencies: bash 4.3+, shfmt, jq

set -uo pipefail

# Re-exec with modern bash if running old bash (namerefs require 4.3+)
if [[ "${BASH_VERSINFO[0]}" -lt 4 || ( "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -lt 3 ) ]]; then
  for try_bash in /opt/homebrew/bin/bash /usr/local/bin/bash /home/linuxbrew/.linuxbrew/bin/bash; do
    if [[ -x "$try_bash" ]]; then
      exec "$try_bash" "$0" "$@"
    fi
  done
  exit 0
fi

# Ensure homebrew tools (jq, shfmt) are in PATH — Claude Code hooks
# run with a minimal PATH that excludes /opt/homebrew/bin.
for p in /opt/homebrew/bin /usr/local/bin /home/linuxbrew/.linuxbrew/bin; do
  [[ -d "$p" ]] && [[ ":$PATH:" != *":$p:"* ]] && PATH="$p:$PATH"
done

DEBUG=false
LAST_MATCHED_CMD=""
LAST_MATCHED_RULE=""
readonly ALLOW_JSON='{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'

debug() { if $DEBUG; then printf '[approve-compound] %s\n' "$*" >&2; fi; }
approve() { printf '%s\n' "$ALLOW_JSON"; exit 0; }
deny() {
  jq -n --arg msg "$1" '{
    hookSpecificOutput: {hookEventName:"PreToolUse", permissionDecision:"deny"},
    systemMessage: $msg
  }'
  exit 2
}

# ---------------------------------------------------------------------------
# Permission loading (single pass over all settings files)
# ---------------------------------------------------------------------------

find_git_root() {
  local toplevel git_dir git_common_dir
  toplevel=$(git rev-parse --show-toplevel 2>/dev/null) || return
  git_dir=$(git rev-parse --git-dir 2>/dev/null)
  git_common_dir=$(git rev-parse --git-common-dir 2>/dev/null)
  if [[ "$git_dir" != "$git_common_dir" ]]; then
    dirname "$git_common_dir"
  else
    printf '%s\n' "$toplevel"
  fi
}

# Populates the caller's allowed_prefixes and denied_prefixes arrays.
load_prefixes() {
  local git_root
  git_root=$(find_git_root 2>/dev/null || true)

  local files=(
    "$HOME/.claude/settings.json"
    "$HOME/.claude/settings.local.json"
  )
  if [[ -n "$git_root" ]]; then
    files+=("$git_root/.claude/settings.json" "$git_root/.claude/settings.local.json")
  else
    files+=(".claude/settings.json" ".claude/settings.local.json")
  fi

  local line
  while IFS= read -r line; do
    case "$line" in
      allow:*) allowed_prefixes+=("${line#allow:}") ;;
      deny:*)  denied_prefixes+=("${line#deny:}") ;;
    esac
  done < <(
    for file in "${files[@]}"; do
      [[ -f "$file" ]] || continue
      debug "Reading prefixes from: $file"
      jq -r '
        def extract_prefix: sub("^Bash\\("; "") | sub("( \\*|\\*|:\\*)\\)$"; "") | sub("\\)$"; "");
        (.permissions.allow[]? // empty | select(startswith("Bash(")) | "allow:" + extract_prefix),
        (.permissions.deny[]?  // empty | select(startswith("Bash(")) | "deny:"  + extract_prefix)
      ' "$file" 2>/dev/null || true
    done | sort -u
  )
}

# ---------------------------------------------------------------------------
# Command detection and parsing (shfmt AST -> individual commands via jq)
# ---------------------------------------------------------------------------

# Returns 0 if the command needs compound parsing (contains shell metacharacters
# that could hide sub-commands: pipes, chains, semicolons, subshells, command
# substitution, process substitution, backticks, or newlines).
needs_compound_parse() {
  # shellcheck disable=SC2016  # $( is a literal pattern, not an expansion
  [[ "$1" == *$'\n'* || "$1" == *$'\r'* || "$1" == *['|&;`(']* || "$1" == *'$('* || "$1" == *'<('* || "$1" == *'>('* ]]
}

# read returns 1 on EOF before delimiter; || true prevents exit under pipefail
read -r -d '' SHFMT_AST_FILTER << 'JQEOF' || true
def get_part_value:
  if (type == "object" | not) then ""
  elif .Type == "Lit" then .Value // ""
  elif .Type == "DblQuoted" then
    "\"" + ([.Parts[]? | get_part_value] | join("")) + "\""
  elif .Type == "SglQuoted" then
    "'" + (.Value // "") + "'"
  elif .Type == "ParamExp" then
    "$" + (.Param.Value // "")
  elif .Type == "CmdSubst" then "$(..)"
  else ""
  end;

def find_cmd_substs:
  if type == "object" then
    if .Type == "CmdSubst" or .Type == "ProcSubst" then .
    elif .Type == "DblQuoted" then .Parts[]? | find_cmd_substs
    elif .Type == "ParamExp" then
      (.Exp?.Word | find_cmd_substs),
      (.Repl?.Orig | find_cmd_substs),
      (.Repl?.With | find_cmd_substs)
    elif .Parts then .Parts[]? | find_cmd_substs
    else empty
    end
  elif type == "array" then .[] | find_cmd_substs
  else empty
  end;

def get_arg_value:
  [.Parts[]? | get_part_value] | join("");

def get_command_string:
  if .Type == "CallExpr" and .Args then
    [.Args[] | get_arg_value] | map(select(length > 0)) | join(" ")
  else empty
  end;

def extract_commands:
  if type == "object" then
    if .Type == "CallExpr" then
      get_command_string,
      (.Args[]? | find_cmd_substs | .Stmts[]? | extract_commands),
      (.Assigns[]?.Value | find_cmd_substs | .Stmts[]? | extract_commands),
      (.Assigns[]?.Array?.Elems[]?.Value | find_cmd_substs | .Stmts[]? | extract_commands),
      (.Redirs[]?.Word | find_cmd_substs | .Stmts[]? | extract_commands)
    elif .Type == "BinaryCmd" then
      (.X | extract_commands), (.Y | extract_commands)
    elif .Type == "Subshell" or .Type == "Block" then
      (.Stmts[]? | extract_commands)
    elif .Type == "CmdSubst" then
      (.Stmts[]? | extract_commands)
    elif .Type == "IfClause" then
      (.Cond[]? | extract_commands),
      (.Then[]? | extract_commands),
      (.Else | extract_commands)
    elif .Type == "WhileClause" or .Type == "UntilClause" then
      (.Cond[]? | extract_commands), (.Do[]? | extract_commands)
    elif .Type == "ForClause" then
      (.Loop.Items[]? | find_cmd_substs | .Stmts[]? | extract_commands),
      (.Do[]? | extract_commands)
    elif .Type == "CaseClause" then
      (.Items[]?.Stmts[]? | extract_commands)
    elif .Type == "FuncDecl" then
      (.Body | extract_commands)
    elif .Type == "DeclClause" then
      (.Args[]?.Value | find_cmd_substs | .Stmts[]? | extract_commands),
      (.Args[]?.Array?.Elems[]?.Value | find_cmd_substs | .Stmts[]? | extract_commands)
    elif .Cmd then
      (.Cmd | extract_commands),
      (.Redirs[]?.Word | find_cmd_substs | .Stmts[]? | extract_commands)
    elif .Stmts then
      (.Stmts[] | extract_commands)
    else
      (.[] | extract_commands)
    end
  elif type == "array" then
    (.[] | extract_commands)
  else empty
  end;

extract_commands | select(length > 0)
JQEOF
readonly SHFMT_AST_FILTER

# Parse compound command into individual commands (NUL-delimited)
parse_compound() {
  local cmd="$1"

  # Normalize [[ \! $x =~ ]] patterns that shfmt can't parse
  if [[ "$cmd" == *"=~"* ]]; then
    cmd=$(sed -E 's/\[\[[[:space:]]*\\?![[:space:]]+(.+)[[:space:]]+=~/! [[ \1 =~/g' <<< "$cmd")
  fi

  local ast
  if ! ast=$(shfmt -ln bash -tojson <<< "$cmd" 2>/dev/null); then
    debug "shfmt parse failed"
    return 1
  fi

  local entry inner
  while IFS= read -r -d '' entry; do
    [[ -z "$entry" ]] && continue
    # Recursively expand shell -c (bash, sh, zsh, dash, ksh with combined flags)
    if [[ "$entry" =~ ^(env[[:space:]]+)?(/[^[:space:]]*/)?((ba|da|k|z)?sh)[[:space:]]+-[a-z]*c[[:space:]]*\'(.*)\'$ ]] ||
       [[ "$entry" =~ ^(env[[:space:]]+)?(/[^[:space:]]*/)?((ba|da|k|z)?sh)[[:space:]]+-[a-z]*c[[:space:]]*\"(.*)\"$ ]] ||
       [[ "$entry" =~ ^(env[[:space:]]+)?(/[^[:space:]]*/)?((ba|da|k|z)?sh)[[:space:]]+-[a-z]*c[[:space:]]+(.+)$ ]]; then
      debug "Recursing into shell -c: ${BASH_REMATCH[5]}"
      if ! parse_compound "${BASH_REMATCH[5]}"; then
        printf '%s\0' "$entry"
      fi
    # Recursively expand eval / exec
    elif [[ "$entry" =~ ^(eval|exec)[[:space:]]+(.+)$ ]]; then
      inner="${BASH_REMATCH[2]}"
      if [[ "$inner" =~ ^\'(.*)\'$ ]] || [[ "$inner" =~ ^\"(.*)\"$ ]]; then
        inner="${BASH_REMATCH[1]}"
      fi
      debug "Recursing into eval/exec: $inner"
      if ! parse_compound "$inner"; then
        printf '%s\0' "$entry"
      fi
    else
      printf '%s\0' "$entry"
    fi
  done < <(jq -j "[$SHFMT_AST_FILTER] | map(. + \"\u0000\") | join(\"\")" <<< "$ast" 2>/dev/null)
}

# ---------------------------------------------------------------------------
# Permission matching
# ---------------------------------------------------------------------------

# Strip leading env var assignments (VAR=val cmd ...) and command launcher
# prefixes (env, xargs, bash/sh/zsh/dash/ksh -c, eval, exec, time, nohup,
# command, builtin) and populate the caller's candidates array via nameref.
strip_prefixes() {
  local full_command="$1"
  local -n out_ref=$2
  local stripped="$full_command"

  # Phase 1: Strip leading VAR=val assignments
  while [[ "$stripped" =~ ^[A-Za-z_][A-Za-z0-9_]*=(\"[^\"]*\"|\'[^\']*\'|[^[:space:]]*)[[:space:]]+(.*) ]]; do
    stripped="${BASH_REMATCH[2]}"
  done

  out_ref=("$full_command")
  [[ "$stripped" != "$full_command" ]] && out_ref+=("$stripped")

  # Phase 2: Strip "env" launcher prefix
  local env_stripped="$stripped"
  if [[ "$env_stripped" =~ ^env[[:space:]]+(.*) ]]; then
    env_stripped="${BASH_REMATCH[1]}"
    # Strip any VAR=val after env
    while [[ "$env_stripped" =~ ^[A-Za-z_][A-Za-z0-9_]*=(\"[^\"]*\"|\'[^\']*\'|[^[:space:]]*)[[:space:]]+(.*) ]]; do
      env_stripped="${BASH_REMATCH[2]}"
    done
    [[ -n "$env_stripped" ]] && out_ref+=("$env_stripped")
  fi

  # Phase 3: Strip "xargs" launcher prefix (from the latest stripped form)
  local xargs_input="$stripped"
  [[ -n "$env_stripped" && "$env_stripped" != "$stripped" ]] && xargs_input="$env_stripped"

  if [[ "$xargs_input" =~ ^xargs[[:space:]]+(.*) ]]; then
    local remainder="${BASH_REMATCH[1]}"
    local -a words=()
    read -ra words <<< "$remainder"
    local i=0 inner_start=-1
    local flags_with_arg="I J n P S s L E"

    while (( i < ${#words[@]} )); do
      local w="${words[$i]}"
      if [[ "$w" == "--" ]]; then
        inner_start=$((i + 1))
        break
      elif [[ "$w" == -* ]]; then
        local flag_char="${w:1:1}"
        if [[ " $flags_with_arg " == *" $flag_char "* ]]; then
          if (( ${#w} > 2 )); then
            # Combined: -n1, -P4 — skip this word only
            ((i++))
          else
            # Separate: -n 1, -I {} — skip this word AND next
            ((i += 2))
          fi
        else
          # Standalone flag (-0, -r, -t, etc.)
          ((i++))
        fi
      else
        inner_start=$i
        break
      fi
    done

    if (( inner_start >= 0 && inner_start < ${#words[@]} )); then
      [[ -n "${words[*]:$inner_start}" ]] && out_ref+=("${words[*]:$inner_start}")
    fi
  fi

  # Final pass: extract inner commands from any candidate that is itself a launcher
  local -a extra=()
  local cand inner_cmd
  for cand in "${out_ref[@]}"; do
    if [[ "$cand" =~ ^(/[^[:space:]]*/)?((ba|da|k|z)?sh)[[:space:]]+-[a-z]*c[[:space:]]+(.+)$ ]]; then
      inner_cmd="${BASH_REMATCH[4]}"
      if [[ "$inner_cmd" =~ ^\'(.*)\'$ ]] || [[ "$inner_cmd" =~ ^\"(.*)\"$ ]]; then
        inner_cmd="${BASH_REMATCH[1]}"
      fi
      [[ -n "$inner_cmd" ]] && extra+=("$inner_cmd")
    elif [[ "$cand" =~ ^(eval|exec)[[:space:]]+(.+)$ ]]; then
      inner_cmd="${BASH_REMATCH[2]}"
      if [[ "$inner_cmd" =~ ^\'(.*)\'$ ]] || [[ "$inner_cmd" =~ ^\"(.*)\"$ ]]; then
        inner_cmd="${BASH_REMATCH[1]}"
      fi
      [[ -n "$inner_cmd" ]] && extra+=("$inner_cmd")
    # Simple prefix launchers: time, nohup, command, builtin
    elif [[ "$cand" =~ ^(time|nohup|command|builtin)[[:space:]]+(.+)$ ]]; then
      inner_cmd="${BASH_REMATCH[2]}"
      # Skip optional single-letter flags (e.g. time -p, command -p)
      while [[ "$inner_cmd" =~ ^-[a-zA-Z][[:space:]]+(.+)$ ]]; do
        inner_cmd="${BASH_REMATCH[1]}"
      done
      [[ -n "$inner_cmd" ]] && extra+=("$inner_cmd")
    fi
  done
  (( ${#extra[@]} > 0 )) && out_ref+=("${extra[@]}")
}

# Check if a command matches any prefix in the given list.
matches_prefix_list() {
  local full_command="$1"
  local -n list_ref=$2
  local label="${3:-}"

  [[ ${#list_ref[@]} -eq 0 ]] && return 1

  local -a candidates=()
  strip_prefixes "$full_command" candidates

  for cmd in "${candidates[@]}"; do
    for prefix in "${list_ref[@]}"; do
      if [[ "$cmd" == "$prefix" ]] || [[ "$cmd" == "$prefix "* ]] || [[ "$cmd" == "$prefix/"* ]]; then
        debug "MATCH ($label): '$cmd' -> '$prefix'"
        LAST_MATCHED_CMD="$cmd"
        LAST_MATCHED_RULE="$prefix"
        return 0
      fi
    done
  done
  return 1
}

# Check a single command against deny then allow lists.
# Returns: 0=allowed, 1=not allowed (denied or unknown)
is_allowed() {
  local cmd="$1"
  if matches_prefix_list "$cmd" denied_prefixes "deny"; then
    return 1
  fi
  matches_prefix_list "$cmd" allowed_prefixes "allow"
}

# Check all commands in the given array. Returns 0 only if every one is allowed.
all_allowed() {
  local -n cmds_ref=$1

  for cmd in "${cmds_ref[@]}"; do
    [[ -z "$cmd" ]] && continue
    if ! is_allowed "$cmd"; then
      debug "Not all commands approved"
      return 1
    fi
  done
  return 0
}

# Check if any command in the given array matches the deny list.
any_denied() {
  local -n cmds_ref=$1
  [[ ${#denied_prefixes[@]} -eq 0 ]] && return 1

  for cmd in "${cmds_ref[@]}"; do
    [[ -z "$cmd" ]] && continue
    if matches_prefix_list "$cmd" denied_prefixes "deny"; then
      debug "Denied segment found: $cmd"
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  local permissions_json="" deny_json="" mode="hook"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --debug) DEBUG=true; shift ;;
      --permissions) permissions_json="$2"; shift 2 ;;
      --deny) deny_json="$2"; shift 2 ;;
      parse) mode="parse"; shift ;;
      *) shift ;;
    esac
  done

  # Guard: dependencies
  for dep in jq shfmt; do
    if ! command -v "$dep" &>/dev/null; then
      printf '[approve-compound-bash] WARNING: %s not found — hook disabled. Install with: brew install %s\n' "$dep" "$dep" >&2
      exit 0
    fi
  done

  # Parse mode: extract commands from stdin (plain text), one per line
  if [[ "$mode" == "parse" ]]; then
    local cmd
    cmd=$(cat)
    [[ -z "$cmd" ]] && exit 0
    if ! needs_compound_parse "$cmd"; then
      printf '%s\n' "$cmd"
    else
      local -a cmds=()
      mapfile -d '' cmds < <(parse_compound "$cmd")
      for c in "${cmds[@]}"; do
        [[ -n "$c" ]] && printf '%s\n' "$c"
      done
    fi
    exit 0
  fi

  # Guard: read hook input
  local input command
  input=$(cat)
  command=$(jq -r '.tool_input.command // empty' <<< "$input")
  [[ -z "$command" ]] && exit 0

  debug "Command: $command"

  # Load permissions (from settings files, or from --permissions/--deny for testing)
  local -a allowed_prefixes=() denied_prefixes=()
  if [[ -n "$permissions_json" ]]; then
    local line
    while IFS= read -r line; do
      [[ -n "$line" ]] && allowed_prefixes+=("$line")
    done < <(jq -r '.[] | sub("^Bash\\("; "") | sub("( \\*|\\*|:\\*)\\)$"; "") | sub("\\)$"; "")' <<< "$permissions_json" 2>/dev/null)
    if [[ -n "$deny_json" ]]; then
      while IFS= read -r line; do
        [[ -n "$line" ]] && denied_prefixes+=("$line")
      done < <(jq -r '.[] | sub("^Bash\\("; "") | sub("( \\*|\\*|:\\*)\\)$"; "") | sub("\\)$"; "")' <<< "$deny_json" 2>/dev/null)
    fi
  else
    load_prefixes
  fi
  debug "Loaded ${#allowed_prefixes[@]} allow, ${#denied_prefixes[@]} deny prefixes"
  [[ ${#allowed_prefixes[@]} -eq 0 ]] && exit 0

  # Simple command — check directly without shfmt parsing
  if ! needs_compound_parse "$command"; then
    debug "Simple command"
    is_allowed "$command" && approve
    matches_prefix_list "$command" denied_prefixes "deny" && deny "Denied: '${LAST_MATCHED_CMD}' matched deny rule '${LAST_MATCHED_RULE}'"
    exit 0
  fi

  # Compound command — parse into segments and check each
  debug "Compound command"
  local -a extracted_commands=()
  mapfile -d '' extracted_commands < <(parse_compound "$command")

  # Parse failure or empty result — fall through to prompt (don't auto-approve
  # unparseable commands that may contain dangerous sub-commands)
  [[ ${#extracted_commands[@]} -eq 0 || -z "${extracted_commands[0]}" ]] && exit 0

  all_allowed extracted_commands && approve

  # Not all approved: actively deny if any segment is in the deny list,
  # otherwise fall through to Claude Code's native permission prompt.
  any_denied extracted_commands && deny "Compound command denied: sub-command '${LAST_MATCHED_CMD}' matched deny rule '${LAST_MATCHED_RULE}'"
  exit 0
}

main "$@"

#!/bin/bash
# block-scope-escape.sh -- PreToolUse hook that prevents the agent from modifying
# its own guardrails in ~/.claude/ and from writing to dangerous system locations.
# Exit code 2 = block the action, stderr message goes to Claude as feedback.

set -euo pipefail

LOG_FILE="$HOME/.claude/guardrail-blocks.log"
HOOK_NAME="block-scope-escape"

log_block() {
  local reason="$1"
  local detail="$2"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "{\"timestamp\":\"$timestamp\",\"hook\":\"$HOOK_NAME\",\"reason\":\"$reason\",\"detail\":\"$detail\",\"user\":\"$(whoami)\"}" >> "$LOG_FILE"
}

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // ""')

# ---------------------------------------------------------------------------
# A. Self-modification prevention -- all tool types
# ---------------------------------------------------------------------------

# For file-based tools (Read, Write, Edit): check file_path
if [ "$TOOL_NAME" = "Read" ] || [ "$TOOL_NAME" = "Write" ] || [ "$TOOL_NAME" = "Edit" ]; then
  FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')

  if [ -n "$FILE_PATH" ]; then
    if echo "$FILE_PATH" | grep -qE '(/\.claude/|^~/.claude)'; then
      log_block "Self-modification via $TOOL_NAME" "$FILE_PATH"
      echo "BLOCKED: Access to '$FILE_PATH' is denied. Modifying files in ~/.claude/ is forbidden -- this directory contains security guardrails that must not be read or altered by the agent." >&2
      exit 2
    fi
  fi

  # File-based tools have no scope-boundary check; allow
  exit 0
fi

# For Bash tool: check command text
if [ "$TOOL_NAME" = "Bash" ]; then
  COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // ""')

  # --- A. Self-modification in Bash commands ---
  CLAUDE_DIR_PATTERNS=(
    '~/.claude'
    '\$HOME/.claude'
    '/\.claude/'
  )
  for pattern in "${CLAUDE_DIR_PATTERNS[@]}"; do
    if echo "$COMMAND" | grep -qF "$pattern" 2>/dev/null || echo "$COMMAND" | grep -qE "$pattern" 2>/dev/null; then
      log_block "Self-modification via Bash" "$COMMAND"
      echo "BLOCKED: Command references ~/.claude/ directory. Modifying guardrail files is forbidden -- this directory contains security guardrails that must not be altered by the agent." >&2
      exit 2
    fi
  done

  # --- B. Scope boundary enforcement -- block writes to system locations ---
  # Only trigger when the command contains a write indicator
  WRITE_INDICATORS='(>|>>|(^|[[:space:]])cp[[:space:]]|(^|[[:space:]])mv[[:space:]]|(^|[[:space:]])tee[[:space:]]|(^|[[:space:]])install[[:space:]]|(^|[[:space:]])rsync[[:space:]])'

  if echo "$COMMAND" | grep -qE "$WRITE_INDICATORS"; then
    # System paths that must not be written to
    BLOCKED_SYSTEM_PATHS=(
      '/etc/'
      '/usr/'
      '/opt/'
      '/System/'
      '/Library/'
    )
    for sys_path in "${BLOCKED_SYSTEM_PATHS[@]}"; do
      if echo "$COMMAND" | grep -qF "$sys_path"; then
        # Allow /var/log for legitimate logging
        if [ "$sys_path" = "/var/" ] && echo "$COMMAND" | grep -qF "/var/log"; then
          continue
        fi
        log_block "Write to system path: $sys_path" "$COMMAND"
        echo "BLOCKED: Command attempts to write to '$sys_path'. Writing to system directories is forbidden. Limit file operations to your project directory." >&2
        exit 2
      fi
    done

    # /var/ checked separately to allow /var/log
    if echo "$COMMAND" | grep -qF "/var/"; then
      if ! echo "$COMMAND" | grep -qE '/var/log(/|$|[[:space:]])'; then
        log_block "Write to system path: /var/" "$COMMAND"
        echo "BLOCKED: Command attempts to write to '/var/'. Writing to system directories is forbidden (except /var/log). Limit file operations to your project directory." >&2
        exit 2
      fi
    fi

    # Shell config files
    SHELL_CONFIGS=(
      '.bashrc'
      '.zshrc'
      '.bash_profile'
      '.zprofile'
      '.profile'
    )
    for config in "${SHELL_CONFIGS[@]}"; do
      if echo "$COMMAND" | grep -qF "$config"; then
        log_block "Write to shell config: $config" "$COMMAND"
        echo "BLOCKED: Command attempts to modify shell config file '$config'. Modifying shell configuration is forbidden. Ask the developer to make shell changes manually." >&2
        exit 2
      fi
    done
  fi

  exit 0
fi

# Unknown tool -- allow by default
exit 0

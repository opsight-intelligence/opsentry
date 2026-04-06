#!/bin/bash
# block-dangerous-commands.sh
# PreToolUse hook — blocks destructive and dangerous bash commands
# Exit code 2 = block the action, stderr message goes to Claude as feedback

set -euo pipefail

LOG_FILE="$HOME/.claude/guardrail-blocks.log"
HOOK_NAME="block-dangerous-commands"

log_block() {
  local reason="$1"
  local detail="$2"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "{\"timestamp\":\"$timestamp\",\"hook\":\"$HOOK_NAME\",\"reason\":\"$reason\",\"detail\":\"$detail\",\"user\":\"$(whoami)\"}" >> "$LOG_FILE"
}

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // ""')

# Only check Bash commands
if [ "$TOOL_NAME" != "Bash" ]; then
  exit 0
fi

COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // ""')

# === DESTRUCTIVE FILE OPERATIONS ===
if echo "$COMMAND" | grep -qE 'rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive|--force|-[a-zA-Z]*f[a-zA-Z]*r)'; then
  log_block "rm -rf or forced recursive deletion" "$COMMAND"
  echo "BLOCKED: rm -rf is not allowed. If you need to delete files, ask the developer to do it manually." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qE '^\s*rm\s+-r\s'; then
  log_block "Recursive deletion (rm -r)" "$COMMAND"
  echo "BLOCKED: Recursive deletion (rm -r) is not allowed. Ask the developer to handle file deletion manually." >&2
  exit 2
fi

# === SUDO ===
if echo "$COMMAND" | grep -qE '(^|\s|;|&&|\|\|)sudo\s'; then
  log_block "sudo command" "$COMMAND"
  echo "BLOCKED: sudo commands are not allowed. You should never need root access." >&2
  exit 2
fi

# === DANGEROUS PERMISSIONS ===
if echo "$COMMAND" | grep -qE 'chmod\s+777'; then
  log_block "chmod 777" "$COMMAND"
  echo "BLOCKED: chmod 777 is not allowed. Use specific permissions like 644 or 755 instead." >&2
  exit 2
fi

# === DISK OPERATIONS ===
if echo "$COMMAND" | grep -qE '(^|\s|;)(mkfs|fdisk|dd\s)'; then
  log_block "Disk-level operation (mkfs/fdisk/dd)" "$COMMAND"
  echo "BLOCKED: Disk-level operations (mkfs, fdisk, dd) are not allowed." >&2
  exit 2
fi

# === KILL SYSTEM PROCESSES ===
if echo "$COMMAND" | grep -qE 'kill\s+-9'; then
  log_block "kill -9" "$COMMAND"
  echo "BLOCKED: kill -9 is not allowed. Use graceful shutdown methods." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qE '(systemctl|service)\s+(stop|restart|disable)'; then
  log_block "systemctl/service stop/restart/disable" "$COMMAND"
  echo "BLOCKED: Stopping or restarting system services is not allowed." >&2
  exit 2
fi

# === PIPE TO SHELL (REMOTE CODE EXECUTION) ===
if echo "$COMMAND" | grep -qE '(curl|wget)\s.*\|\s*(sh|bash|zsh)'; then
  log_block "Pipe to shell (curl/wget | sh/bash)" "$COMMAND"
  echo "BLOCKED: Downloading and piping to shell is not allowed. Download the script first, review it, then run it." >&2
  exit 2
fi

# === DATABASE DESTRUCTIVE COMMANDS ===
if echo "$COMMAND" | grep -qiE '(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)'; then
  log_block "DROP TABLE/DATABASE or TRUNCATE" "$COMMAND"
  echo "BLOCKED: DROP TABLE, DROP DATABASE, and TRUNCATE TABLE are not allowed via the agent." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qiE 'DELETE\s+FROM\s+\w+\s*;' ; then
  log_block "DELETE FROM without WHERE clause" "$COMMAND"
  echo "BLOCKED: DELETE FROM without a WHERE clause is not allowed. Always specify a WHERE condition." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qiE 'UPDATE\s+\w+\s+SET\s.*;\s*$' | grep -qivE 'WHERE'; then
  log_block "UPDATE without WHERE clause" "$COMMAND"
  echo "BLOCKED: UPDATE without a WHERE clause is not allowed." >&2
  exit 2
fi

exit 0

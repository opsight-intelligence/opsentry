#!/bin/bash
# block-git-commands.sh
# PreToolUse hook — blocks Claude Code from executing any git commands
# Exit code 2 = block the action, stderr message goes to Claude as feedback

set -euo pipefail

LOG_FILE="$HOME/.claude/guardrail-blocks.log"
HOOK_NAME="block-git-commands"

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

# Block any command that starts with git or contains git as a chained command
if echo "$COMMAND" | grep -qE '(^|\s|;|&&|\|\|)git\s'; then
  log_block "Git command detected" "$COMMAND"
  echo "BLOCKED: Git commands are not allowed. Write the git command as text for the developer to review and run manually." >&2
  exit 2
fi

exit 0

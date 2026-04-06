#!/bin/bash
# block-environment-escape.sh
# PreToolUse hook that blocks commands which could escape the local development environment.
# It prevents SSH/SCP to remote hosts, dangerous Docker operations, production env var access,
# destructive Terraform commands, and destructive kubectl operations.
# Exit code 2 = block the action, stderr message goes to Claude as feedback.

set -euo pipefail

LOG_FILE="$HOME/.claude/guardrail-blocks.log"
HOOK_NAME="block-environment-escape"

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

# === SSH / SCP TO REMOTE HOSTS ===
if echo "$COMMAND" | grep -qE '(^|\s|;|&&|\|\|)(ssh|scp)\s'; then
  log_block "SSH/SCP to remote host" "$COMMAND"
  echo "BLOCKED: SSH and SCP commands are not allowed. They can be used to access remote hosts outside the local environment." >&2
  exit 2
fi

# === RSYNC WITH REMOTE TARGETS (contains user@host: or host: pattern) ===
if echo "$COMMAND" | grep -qE '(^|\s|;|&&|\|\|)rsync\s'; then
  if echo "$COMMAND" | grep -qE '[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:|[a-zA-Z0-9._-]+:'; then
    log_block "rsync to remote target" "$COMMAND"
    echo "BLOCKED: rsync with remote targets is not allowed. Local rsync (without host: patterns) is permitted." >&2
    exit 2
  fi
fi

# === DOCKER ESCAPE OPERATIONS ===
if echo "$COMMAND" | grep -qE '(^|\s|;|&&|\|\|)docker\s+(run|exec|cp|build)\s'; then
  log_block "Docker escape operation" "$COMMAND"
  echo "BLOCKED: docker run, exec, cp, and build are not allowed. They could escape sandboxing. Read-only commands (ps, logs, images) are permitted." >&2
  exit 2
fi

# === PRODUCTION ENVIRONMENT VARIABLE ACCESS ===
if echo "$COMMAND" | grep -qE '(^|\s|;|&&|\|\|)(echo|printf)\s+.*\$\{?PROD(UCTION)?_'; then
  log_block "Production env var access" "$COMMAND"
  echo "BLOCKED: Reading production environment variables (PROD_*, PRODUCTION_*) is not allowed." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qE '(^|\s|;|&&|\|\|)printenv\s+PROD(UCTION)?_'; then
  log_block "Production env var access via printenv" "$COMMAND"
  echo "BLOCKED: Reading production environment variables (PROD_*, PRODUCTION_*) is not allowed." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qE 'env\s*\|\s*grep\s+.*PROD(UCTION)?_'; then
  log_block "Production env var access via env grep" "$COMMAND"
  echo "BLOCKED: Grepping for production environment variables (PROD_*, PRODUCTION_*) is not allowed." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qE '(^|\s|;|&&|\|\|)export\s+PROD(UCTION)?_'; then
  log_block "Production env var export" "$COMMAND"
  echo "BLOCKED: Exporting production environment variables (PROD_*, PRODUCTION_*) is not allowed." >&2
  exit 2
fi

# === TERRAFORM DESTRUCTIVE COMMANDS ===
if echo "$COMMAND" | grep -qE '(^|\s|;|&&|\|\|)terraform\s+(apply|destroy|import)\s*'; then
  log_block "Terraform destructive command" "$COMMAND"
  echo "BLOCKED: terraform apply, destroy, and import are not allowed. Use terraform plan, fmt, or validate instead." >&2
  exit 2
fi

# === KUBECTL DESTRUCTIVE OPERATIONS ===
if echo "$COMMAND" | grep -qE '(^|\s|;|&&|\|\|)kubectl\s+(delete|exec|apply)\s'; then
  log_block "kubectl destructive operation" "$COMMAND"
  echo "BLOCKED: kubectl delete, exec, and apply are not allowed. Read-only commands (get, describe, logs) are permitted." >&2
  exit 2
fi

exit 0

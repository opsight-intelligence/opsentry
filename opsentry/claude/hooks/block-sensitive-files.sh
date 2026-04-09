#!/bin/bash
# block-sensitive-files.sh
# PreToolUse hook — blocks Claude Code from reading sensitive files
# Exit code 2 = block the action, stderr message goes to Claude as feedback

set -euo pipefail

LOG_FILE="$HOME/.claude/guardrail-blocks.log"
HOOK_NAME="block-sensitive-files"

log_block() {
  local reason="$1"
  local detail="$2"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "{\"timestamp\":\"$timestamp\",\"hook\":\"$HOOK_NAME\",\"reason\":\"$reason\",\"detail\":\"$detail\",\"user\":\"$(whoami)\"}" >> "$LOG_FILE"
}

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // ""')

# Get the file path depending on the tool
FILE_PATH=""
if [ "$TOOL_NAME" = "Read" ]; then
  FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')
elif [ "$TOOL_NAME" = "Bash" ]; then
  COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // ""')
  # Check if bash command references sensitive files
  SENSITIVE_PATTERNS=(
    '\.env'
    'credentials\.'
    'secret'
    'token'
    '\.pem'
    '\.key$'
    '\.crt$'
    '\.p12'
    '\.pfx'
    '\.keystore'
    '\.jks'
    '\.ssh/'
    '\.aws/'
    '\.azure/'
    '\.gcloud/'
    'snowflake\.config'
    'profiles\.yml'
    'connections\.toml'
  )
  for pattern in "${SENSITIVE_PATTERNS[@]}"; do
    if echo "$COMMAND" | grep -qiE "$pattern"; then
      log_block "Matched pattern: $pattern" "$COMMAND"
      echo "BLOCKED: Command references a sensitive file pattern ($pattern). Do not access credential files, .env files, or secret files. Ask the developer to provide the specific values you need." >&2
      exit 2
    fi
  done
  exit 0
fi

# For Read tool — check against blocked patterns
if [ -n "$FILE_PATH" ]; then
  BLOCKED_PATTERNS=(
    '\.env$'
    '\.env\.'
    'credentials\.json'
    'credentials\.yaml'
    'credentials\.toml'
    'secret'
    'token'
    '\.pem$'
    '\.key$'
    '\.crt$'
    '\.p12$'
    '\.pfx$'
    '\.keystore$'
    '\.jks$'
    '/\.ssh/'
    '/\.aws/'
    '/\.azure/'
    '/\.gcloud/'
    'snowflake\.config'
    'profiles\.yml'
    'connections\.toml'
    '/secrets/'
    '/credentials/'
    '/private/'
    '/keys/'
  )
  for pattern in "${BLOCKED_PATTERNS[@]}"; do
    if echo "$FILE_PATH" | grep -qiE "$pattern"; then
      log_block "Matched pattern: $pattern" "$FILE_PATH"
      echo "BLOCKED: Access to '$FILE_PATH' is denied by company security policy. This file matches a protected pattern ($pattern). Ask the developer to provide the specific non-sensitive values you need." >&2
      exit 2
    fi
  done
fi

exit 0

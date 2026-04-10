#!/bin/bash
# block-data-exfiltration.sh
# PreToolUse hook that blocks data exfiltration attempts via curl/wget POST with file refs,
# base64 encoding of sensitive files, writes to world-readable locations, clipboard
# exfiltration of sensitive data, and netcat outbound data channels.
# Exit code 2 = block the action, stderr message goes to Claude as feedback.

set -euo pipefail

LOG_FILE="$HOME/.claude/guardrail-blocks.log"
HOOK_NAME="block-data-exfiltration"

SENSITIVE_PATTERNS='\.env|credentials|secret|token|\.pem|\.key|\.crt|\.p12|\.pfx|\.keystore|\.jks|\.ssh|\.aws|\.azure|\.gcloud|snowflake\.config|profiles\.yml|connections\.toml'

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

# Optional path prefix for matching commands invoked via full path
P='(/\S+/)?'

# === CURL/WGET POST WITH FILE REFERENCES ===
# Catches both spaced (-d @file) and unspaced (-d@file) variants
if echo "$COMMAND" | grep -qE "${P}curl\s.*(-d\s*@|-F\s*\S*=@|--data\s*@|--data-binary\s*@|--data-urlencode\s*@)"; then
  log_block "curl POST with file reference" "$COMMAND"
  echo "BLOCKED: curl with file upload (@file) is not allowed. This could exfiltrate local files to an external server." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qE "${P}wget\s.*--post-file"; then
  log_block "wget --post-file" "$COMMAND"
  echo "BLOCKED: wget --post-file is not allowed. This could exfiltrate local files to an external server." >&2
  exit 2
fi

# === BASE64 ENCODING OF SENSITIVE FILES ===
if echo "$COMMAND" | grep -qE "${P}base64\s.*(${SENSITIVE_PATTERNS})"; then
  log_block "base64 encoding of sensitive file" "$COMMAND"
  echo "BLOCKED: base64 encoding of sensitive files is not allowed. This is a common data exfiltration technique." >&2
  exit 2
fi

# Catches both "cat .env | base64" and "cat .env|base64" (no space before pipe)
if echo "$COMMAND" | grep -qE "cat\s.*(${SENSITIVE_PATTERNS}).*\|[ \t]*${P}(base64|openssl\s+enc|xxd)"; then
  log_block "cat sensitive file piped to encoder" "$COMMAND"
  echo "BLOCKED: Piping sensitive files through encoding tools is not allowed. This is a common data exfiltration technique." >&2
  exit 2
fi

# === WRITES TO WORLD-READABLE OR TEMP LOCATIONS ===
if echo "$COMMAND" | grep -qE '(cp|mv|tee|cat\s.*>)\s.*(\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)'; then
  log_block "Write to world-readable temp location" "$COMMAND"
  echo "BLOCKED: Writing files to /tmp/, /var/tmp/, or /dev/shm/ is not allowed. These locations are world-readable and pose a data exfiltration risk." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qE '>{1,2}\s*(\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)'; then
  log_block "Redirect to world-readable temp location" "$COMMAND"
  echo "BLOCKED: Redirecting output to /tmp/, /var/tmp/, or /dev/shm/ is not allowed. These locations are world-readable and pose a data exfiltration risk." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qE 'chmod\s+777'; then
  log_block "chmod 777 (world-readable permissions)" "$COMMAND"
  echo "BLOCKED: chmod 777 is not allowed. Setting world-readable/writable/executable permissions is a security risk." >&2
  exit 2
fi

# === CLIPBOARD EXFILTRATION OF SENSITIVE DATA ===
if echo "$COMMAND" | grep -qE '(pbcopy|xclip|xsel|wl-copy)'; then
  if echo "$COMMAND" | grep -qE "(${SENSITIVE_PATTERNS})"; then
    log_block "Clipboard exfiltration of sensitive data" "$COMMAND"
    echo "BLOCKED: Copying sensitive file contents to the clipboard is not allowed." >&2
    exit 2
  fi
fi

# === NC/NETCAT OUTBOUND DATA CHANNELS ===
if echo "$COMMAND" | grep -qE "(^|\s|;|&&|\|\|)${P}(nc|netcat|ncat|socat)\s"; then
  log_block "netcat/socat outbound data channel" "$COMMAND"
  echo "BLOCKED: nc/netcat/ncat/socat commands are not allowed. These can be used to exfiltrate data over the network." >&2
  exit 2
fi

exit 0

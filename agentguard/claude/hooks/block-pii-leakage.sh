#!/bin/bash
# block-pii-leakage.sh
# PreToolUse hook -- blocks Claude Code from writing PII patterns into source files.
# Checks Write and Edit tool inputs for SSNs, credit card numbers, and similar patterns.
# Exit code 2 = block the action, stderr message goes to Claude as feedback.

set -euo pipefail

LOG_FILE="$HOME/.claude/guardrail-blocks.log"
HOOK_NAME="block-pii-leakage"

log_block() {
  local reason="$1"
  local detail="$2"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "{\"timestamp\":\"$timestamp\",\"hook\":\"$HOOK_NAME\",\"reason\":\"$reason\",\"detail\":\"$detail\",\"user\":\"$(whoami)\"}" >> "$LOG_FILE"
}

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // ""')

# Only check Write, Edit, and Bash tools
if [ "$TOOL_NAME" != "Write" ] && [ "$TOOL_NAME" != "Edit" ] && [ "$TOOL_NAME" != "Bash" ]; then
  exit 0
fi

# Extract the content to scan based on tool type
CONTENT=""
if [ "$TOOL_NAME" = "Write" ]; then
  CONTENT=$(echo "$INPUT" | jq -r '.tool_input.content // ""')
elif [ "$TOOL_NAME" = "Edit" ]; then
  CONTENT=$(echo "$INPUT" | jq -r '.tool_input.new_string // ""')
elif [ "$TOOL_NAME" = "Bash" ]; then
  CONTENT=$(echo "$INPUT" | jq -r '.tool_input.command // ""')
fi

if [ -z "$CONTENT" ]; then
  exit 0
fi

# ============================================================
# Default PII patterns (US locale)
# To add locale-specific patterns, append sections below.
# ============================================================

# --- US Social Security Number (XXX-XX-XXXX) ---
SSN_MATCH=$(echo "$CONTENT" | grep -oE '\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b' | head -1 || true)
if [ -n "$SSN_MATCH" ]; then
  # Allow well-known synthetic test SSNs
  IS_SYNTHETIC=$(echo "$SSN_MATCH" | grep -cE '^(000-00-0000|555-55-5555)$' || true)
  if [ "$IS_SYNTHETIC" -eq 0 ]; then
    log_block "US SSN pattern detected" "$SSN_MATCH"
    echo "BLOCKED: Content contains a pattern matching a US Social Security Number ($SSN_MATCH). Use synthetic test data like 000-00-0000 or 555-55-5555 instead. Never include real PII in source code." >&2
    exit 2
  fi
fi

# --- Credit Card Numbers (Visa, Mastercard, Amex, Discover) ---
CC_MATCH=$(echo "$CONTENT" | grep -oE '\b(4[0-9]{3}|5[1-5][0-9]{2}|6(011|5[0-9]{2}))[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{1,4}\b' | head -1 || true)
if [ -z "$CC_MATCH" ]; then
  # Try Amex pattern separately: 3[47]XX-XXXXXX-XXXXX
  CC_MATCH=$(echo "$CONTENT" | grep -oE '\b3[47][0-9]{2}[- ]?[0-9]{6}[- ]?[0-9]{5}\b' | head -1 || true)
fi
if [ -n "$CC_MATCH" ]; then
  log_block "Credit card number pattern detected" "$CC_MATCH"
  echo "BLOCKED: Content contains a pattern matching a credit card number. Use synthetic test data like 4111-1111-1111-1111 instead. Never include real PII in source code." >&2
  exit 2
fi

# ============================================================
# Optional locale: KR (Korean Resident Registration Number)
# Remove or comment this section if not needed.
# ============================================================

# --- Korean Resident Registration Number (YYMMDD-NNNNNNN) ---
RRN_MATCH=$(echo "$CONTENT" | grep -oE '\b[0-9]{6}-[0-9]{7}\b' | head -1 || true)
if [ -n "$RRN_MATCH" ]; then
  log_block "Korean RRN pattern detected" "$RRN_MATCH"
  echo "BLOCKED: Content contains a pattern matching a Korean Resident Registration Number ($RRN_MATCH). Use synthetic test data instead. Never include real PII in source code." >&2
  exit 2
fi

exit 0

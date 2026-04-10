#!/bin/bash
# block-package-install.sh
# PreToolUse hook that blocks package installations from untrusted or arbitrary sources.
# It detects pip, npm, gem, and go installs from custom registries, git URLs, and direct URLs.
# Curl/wget piped to package managers is also blocked.

set -euo pipefail

LOG_FILE="$HOME/.claude/guardrail-blocks.log"
HOOK_NAME="block-package-install"

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

# === PIP INSTALL FROM ARBITRARY SOURCES ===
# Catches: pip install -i url, pip install --index-url url, pip install --index-url=url
# Also catches: python -m pip install, python3 -m pip install
if echo "$COMMAND" | grep -qE "(${P}pip[3]?|(python|python3)\s+-m\s+pip)\s+install\s.*(-i[ =]|--index-url[ =]|--extra-index-url[ =])"; then
  log_block "pip install with custom index URL" "$COMMAND"
  echo "BLOCKED: pip install with --index-url or -i pointing to a custom registry is not allowed. Use the default PyPI registry." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qE "(${P}pip[3]?|(python|python3)\s+-m\s+pip)\s+install\s.*git\+"; then
  log_block "pip install from git URL" "$COMMAND"
  echo "BLOCKED: pip install from a git URL is not allowed. Only install packages from PyPI." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qE "(${P}pip[3]?|(python|python3)\s+-m\s+pip)\s+install\s.*https?://"; then
  log_block "pip install from direct URL" "$COMMAND"
  echo "BLOCKED: pip install from a direct URL is not allowed. Only install packages from PyPI." >&2
  exit 2
fi

# === NPM INSTALL FROM ARBITRARY SOURCES ===
# Catches both --registry url and --registry=url
if echo "$COMMAND" | grep -qE "${P}npm\s+install\s.*--registry[ =]"; then
  log_block "npm install with custom registry" "$COMMAND"
  echo "BLOCKED: npm install with --registry pointing to a custom registry is not allowed. Use the default npm registry." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qE "${P}npm\s+install\s.*git(\+https?|\+ssh|://)"; then
  log_block "npm install from git URL" "$COMMAND"
  echo "BLOCKED: npm install from a git URL is not allowed. Only install packages from the npm registry." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qE "${P}npm\s+install\s.*https?://"; then
  log_block "npm install from tarball URL" "$COMMAND"
  echo "BLOCKED: npm install from a direct URL is not allowed. Only install packages from the npm registry." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qE "${P}npm\s+install\s+[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+"; then
  log_block "npm install from GitHub shorthand" "$COMMAND"
  echo "BLOCKED: npm install from GitHub shorthand (user/repo) is not allowed. Only install packages from the npm registry." >&2
  exit 2
fi

# === GEM INSTALL FROM ARBITRARY SOURCES ===
# Catches both --source url and --source=url
if echo "$COMMAND" | grep -qE "${P}gem\s+install\s.*--source[ =]"; then
  log_block "gem install with custom source" "$COMMAND"
  echo "BLOCKED: gem install with --source pointing to a custom registry is not allowed. Use the default RubyGems registry." >&2
  exit 2
fi

# === GO INSTALL FROM ARBITRARY SOURCES ===
if echo "$COMMAND" | grep -qE "${P}go\s+install\s+https?://"; then
  log_block "go install from URL" "$COMMAND"
  echo "BLOCKED: go install from a direct URL is not allowed. Use standard Go module paths." >&2
  exit 2
fi

# === CURL/WGET PIPED TO PACKAGE MANAGERS ===
# Catches both "curl url | pip" and "curl url|pip" (no space)
if echo "$COMMAND" | grep -qE "(${P}curl|${P}wget)\s.*\|[ \t]*(pip[3]?|npm|gem|go)\s"; then
  log_block "curl/wget piped to package manager" "$COMMAND"
  echo "BLOCKED: Piping curl/wget output to a package manager is not allowed. Download files first, review them, then install." >&2
  exit 2
fi

exit 0

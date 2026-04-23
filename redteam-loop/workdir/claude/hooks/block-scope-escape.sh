#!/bin/bash
# block-scope-escape.sh -- PreToolUse hook that prevents the agent from modifying
# its own guardrails in ~/.claude/ and from writing to dangerous system locations.
# Exit code 2 = block the action, stderr message goes to Claude as feedback.
#
# Path checks use word-boundary anchoring (whitespace, quote, =, backtick, or
# start-of-line) so that legitimate paths containing system-path substrings
# are NOT blocked. Specifically:
#   - project-local .claude/ directories (e.g., ~/Desktop/repos/x/.claude/)
#     are allowed; only $HOME/.claude/ is the protected install target
#   - ~/Library/ on macOS is allowed (only system /Library/ is blocked)
#   - /var/folders/ (macOS per-user temp) and /var/log/ are allowed
# File paths on Read/Write/Edit are resolved via realpath (with fallback)
# so symlinks pointing into $HOME/.claude/ are still caught.

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

# ---------------------------------------------------------------------------
# Path resolution helpers
# ---------------------------------------------------------------------------

# Expand a leading ~/ to $HOME, then run realpath if available.
# For non-existent paths (e.g., Write to a new file), resolve the parent
# directory and re-attach the basename. Falls back to the unresolved path
# when realpath is not installed (best-effort symlink resolution).
resolve_path() {
  local p="$1"
  # Expand a leading ~/ via substring offset (avoid `${p#~/}` because bash
  # applies tilde expansion to the ~ inside the pattern, which silently
  # produces ~/foo -> $HOME/~/foo instead of $HOME/foo).
  case "$p" in
    "~") p="$HOME" ;;
    "~/"*) p="$HOME/${p:2}" ;;
  esac

  if [ -e "$p" ]; then
    if command -v realpath >/dev/null 2>&1; then
      realpath "$p" 2>/dev/null || echo "$p"
    else
      echo "$p"
    fi
    return
  fi

  # Path doesn't exist yet (e.g., Write to a new file). Resolve the parent
  # so a symlinked parent dir is still caught.
  local parent base resolved_parent
  parent=$(dirname "$p")
  base=$(basename "$p")
  if [ -e "$parent" ] && command -v realpath >/dev/null 2>&1; then
    resolved_parent=$(realpath "$parent" 2>/dev/null || echo "$parent")
    echo "$resolved_parent/$base"
  else
    echo "$p"
  fi
}

# Return 0 (success) iff the resolved absolute path is $HOME/.claude or
# any descendant. Compares against BOTH the unresolved $HOME and the
# realpath-resolved $HOME so the macOS /var -> /private/var symlink (which
# affects tempdirs and any path-resolved file_path) does not cause a miss.
is_under_home_claude() {
  local resolved="$1"
  local home_claude="$HOME/.claude"
  local resolved_home_claude="$home_claude"
  if command -v realpath >/dev/null 2>&1; then
    local resolved_home
    resolved_home=$(realpath "$HOME" 2>/dev/null || echo "$HOME")
    resolved_home_claude="$resolved_home/.claude"
  fi
  case "$resolved" in
    "$home_claude") return 0 ;;
    "$home_claude"/*) return 0 ;;
    "$resolved_home_claude") return 0 ;;
    "$resolved_home_claude"/*) return 0 ;;
  esac
  return 1
}

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // ""')

# ---------------------------------------------------------------------------
# A. Self-modification prevention -- Read, Write, Edit
# ---------------------------------------------------------------------------

if [ "$TOOL_NAME" = "Read" ] || [ "$TOOL_NAME" = "Write" ] || [ "$TOOL_NAME" = "Edit" ]; then
  FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')

  if [ -n "$FILE_PATH" ]; then
    RESOLVED=$(resolve_path "$FILE_PATH")
    if is_under_home_claude "$RESOLVED"; then
      log_block "Self-modification via $TOOL_NAME" "$FILE_PATH"
      echo "BLOCKED: Access to '$FILE_PATH' (resolves to '$RESOLVED') is denied. Modifying files in ~/.claude/ is forbidden -- this directory contains security guardrails that must not be read or altered by the agent." >&2
      exit 2
    fi
  fi

  # File-based tools have no additional scope-boundary check; allow.
  exit 0
fi

# ---------------------------------------------------------------------------
# B. Bash branch
# ---------------------------------------------------------------------------

if [ "$TOOL_NAME" = "Bash" ]; then
  COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // ""')

  # Boundary character class: start-of-line, whitespace, =, backtick, single
  # or double quote. Used to anchor system path matches so substring matches
  # against /Library/ inside ~/Library/ don't fire.
  # In double-quoted bash strings: \` for backtick, \" for dquote, \$ for $.
  BOUNDARY="(^|[[:space:]=\`\"'])"
  END_BOUNDARY="(/|\$|[[:space:]\"'])"

  # --- B1. Self-modification: ~/.claude/ in any form ---

  # Literal forms (uniquely identifiable, fixed-string match is safe):
  CLAUDE_LITERAL_FORMS=(
    '~/.claude'
    '$HOME/.claude'
    '${HOME}/.claude'
  )
  for form in "${CLAUDE_LITERAL_FORMS[@]}"; do
    if echo "$COMMAND" | grep -qF "$form"; then
      log_block "Self-modification via Bash (literal $form)" "$COMMAND"
      echo "BLOCKED: Command references $form. Modifying guardrail files is forbidden -- this directory contains security guardrails that must not be altered by the agent." >&2
      exit 2
    fi
  done

  # Expanded HOME path (e.g., /Users/utku/.claude/...). Anchor to a path-arg
  # boundary so /Users/utku/Desktop/repos/x/.claude/ does NOT match.
  # Escape the dot in $HOME for regex (other regex specials are extremely
  # rare in usernames; we accept that residual).
  HOME_RE="${HOME//./\\.}"
  EXPANDED_CLAUDE_REGEX="${BOUNDARY}${HOME_RE}/\\.claude${END_BOUNDARY}"
  if echo "$COMMAND" | grep -qE "$EXPANDED_CLAUDE_REGEX"; then
    log_block "Self-modification via Bash (expanded HOME path)" "$COMMAND"
    echo "BLOCKED: Command references the expanded \$HOME/.claude/ path. Modifying guardrail files is forbidden -- this directory contains security guardrails that must not be altered by the agent." >&2
    exit 2
  fi

  # --- B2. Scope boundary enforcement: writes to system locations ---
  # Only trigger when the command actually writes (>, >>, cp, mv, tee, install,
  # rsync, dd, chmod, sed -i).
  WRITE_INDICATORS='(>|>>|(^|[[:space:]])(cp|mv|tee|install|rsync|dd|chmod)[[:space:]]|sed[[:space:]]+-[a-zA-Z]*i)'

  if echo "$COMMAND" | grep -qE "$WRITE_INDICATORS"; then
    # System paths anchored at path-arg boundary. ~/Library/ is NOT matched
    # because the boundary requires whitespace/quote/start before /Library/.
    SYS_REGEX="${BOUNDARY}/(etc|usr|opt|System|Library)${END_BOUNDARY}"
    if echo "$COMMAND" | grep -qE "$SYS_REGEX"; then
      MATCH=$(echo "$COMMAND" | grep -oE '/(etc|usr|opt|System|Library)/' | head -1 || true)
      log_block "Write to system path: $MATCH" "$COMMAND"
      echo "BLOCKED: Command attempts to write to '$MATCH' (system path). Writing to system directories is forbidden. Limit file operations to your project directory or your home directory." >&2
      exit 2
    fi

    # /var/ — block by default, exempt /var/log/ (logging) and /var/folders/
    # (macOS per-user temp dir, where mktemp puts things). /var/tmp/ remains
    # blocked per CLAUDE.md rule 12 (data exfiltration prevention).
    VAR_REGEX="${BOUNDARY}/var/"
    if echo "$COMMAND" | grep -qE "$VAR_REGEX"; then
      # Pull every /var/<segment> reference out of the command and check
      # whether at least one is NOT in the allow list. Allow segments:
      # log, folders. Anything else (cache, tmp, lib, www, ...) is blocked.
      VAR_BAD=""
      while IFS= read -r seg; do
        case "$seg" in
          /var/log|/var/log/*) ;;
          /var/folders|/var/folders/*) ;;
          *) VAR_BAD="$seg"; break ;;
        esac
      done < <(echo "$COMMAND" | grep -oE '/var/[a-zA-Z0-9_.-]+' || true)
      if [ -n "$VAR_BAD" ]; then
        log_block "Write to /var/ system path: $VAR_BAD" "$COMMAND"
        echo "BLOCKED: Command attempts to write to '$VAR_BAD'. Writing to /var/ is forbidden except /var/log/ (logging) and /var/folders/ (macOS temp). Limit file operations to your project directory." >&2
        exit 2
      fi
    fi

    # Shell config files. Match the filename at a boundary so foo.bashrc.bak
    # doesn't false-positive on ".bashrc" substring.
    SHELL_CONFIG_REGEX="(^|[[:space:]=\`\"'/])\\.(bashrc|zshrc|bash_profile|zprofile|profile)(\$|[[:space:]\"'])"
    if echo "$COMMAND" | grep -qE "$SHELL_CONFIG_REGEX"; then
      MATCH=$(echo "$COMMAND" | grep -oE '\.(bashrc|zshrc|bash_profile|zprofile|profile)' | head -1 || true)
      log_block "Write to shell config: $MATCH" "$COMMAND"
      echo "BLOCKED: Command attempts to modify shell config file '$MATCH'. Modifying shell configuration is forbidden. Ask the developer to make shell changes manually." >&2
      exit 2
    fi
  fi

  exit 0
fi

# Unknown tool -- allow by default
exit 0

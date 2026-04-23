#!/bin/bash
# patrol.sh — Compliance Patrol: extended audit beyond verify.sh
# Scans for unexpected persistence, hook tampering, and security posture drift.
# Run manually: ./ai-guardrails/patrol.sh
# Schedule via: opsentry patrol --schedule

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${OPSENTRY_PKG_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
CLAUDE_HOME="$HOME/.claude"
HOOKS_DIR="$CLAUDE_HOME/hooks"
LOG_FILE="$CLAUDE_HOME/guardrail-blocks.log"
PASS=0
WARN=0
FAIL=0

log_finding() {
  local severity="$1"
  local finding="$2"
  local detail="$3"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "{\"timestamp\":\"$timestamp\",\"hook\":\"patrol\",\"reason\":\"$finding\",\"detail\":\"$detail\",\"user\":\"$(whoami)\",\"severity\":\"$severity\"}" >> "$LOG_FILE"
}

echo ""
echo "============================================"
echo "  OpSentry Compliance Patrol"
echo "============================================"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# --- 1. Run standard verification first ---
# verify.sh exits non-zero whenever it finds a problem, which is exactly when
# patrol is most useful. Run it with `set -e` and pipefail temporarily off so
# patrol.sh continues into the persistence / hook integrity / baseline /
# block log / immutability sections instead of aborting at the first failure.
# PIPESTATUS[0] still captures verify.sh's actual exit code.
echo "--- Standard Verification ---"
set +e
VERIFY_OUTPUT=$(bash "$SCRIPT_DIR/verify.sh" 2>&1)
VERIFY_EXIT=$?
set -e
while IFS= read -r line; do
  [ -z "$line" ] && continue
  case "$line" in
    *"  PASS  "*|*"  FAIL  "*|*"  WARN  "*)
      echo "$line"
      case "$line" in
        *"  PASS  "*) PASS=$((PASS + 1)) ;;
        *"  WARN  "*) WARN=$((WARN + 1)) ;;
        *"  FAIL  "*)
          FAIL=$((FAIL + 1))
          log_finding "high" "Verify check failed" "$(echo "$line" | tr -d '"\\')"
          ;;
      esac
      ;;
  esac
done <<< "$VERIFY_OUTPUT"
echo ""

# --- 2. Persistence scan: unexpected scheduled tasks ---
echo "--- Persistence Scan ---"

# macOS LaunchAgents
if [ -d "$HOME/Library/LaunchAgents" ]; then
  SUSPICIOUS_AGENTS=$(find "$HOME/Library/LaunchAgents" -name "*.plist" -newer "$CLAUDE_HOME/VERSION" 2>/dev/null | grep -v 'com.apple\|com.google\|com.microsoft\|com.docker\|com.jetbrains\|com.anthropic' || true)
  if [ -n "$SUSPICIOUS_AGENTS" ]; then
    echo "  WARN  New LaunchAgents found since last install:"
    echo "$SUSPICIOUS_AGENTS" | while read -r f; do echo "         $f"; done
    log_finding "medium" "New LaunchAgent detected" "$SUSPICIOUS_AGENTS"
    WARN=$((WARN + 1))
  else
    echo "  PASS  No suspicious LaunchAgents"
    PASS=$((PASS + 1))
  fi
fi

# macOS LaunchDaemons (user-level)
if [ -d "$HOME/Library/LaunchDaemons" ]; then
  SUSPICIOUS_DAEMONS=$(find "$HOME/Library/LaunchDaemons" -name "*.plist" 2>/dev/null || true)
  if [ -n "$SUSPICIOUS_DAEMONS" ]; then
    echo "  WARN  User LaunchDaemons found (unusual):"
    echo "$SUSPICIOUS_DAEMONS" | while read -r f; do echo "         $f"; done
    log_finding "medium" "User LaunchDaemon detected" "$SUSPICIOUS_DAEMONS"
    WARN=$((WARN + 1))
  else
    echo "  PASS  No user LaunchDaemons"
    PASS=$((PASS + 1))
  fi
fi

# Linux systemd user services
if [ -d "$HOME/.config/systemd/user" ]; then
  SUSPICIOUS_SERVICES=$(find "$HOME/.config/systemd/user" -name "*.service" -newer "$CLAUDE_HOME/VERSION" 2>/dev/null || true)
  if [ -n "$SUSPICIOUS_SERVICES" ]; then
    echo "  WARN  New systemd user services found since last install:"
    echo "$SUSPICIOUS_SERVICES" | while read -r f; do echo "         $f"; done
    log_finding "medium" "New systemd user service detected" "$SUSPICIOUS_SERVICES"
    WARN=$((WARN + 1))
  else
    echo "  PASS  No suspicious systemd user services"
    PASS=$((PASS + 1))
  fi
fi

# Linux autostart
if [ -d "$HOME/.config/autostart" ]; then
  SUSPICIOUS_AUTOSTART=$(find "$HOME/.config/autostart" -name "*.desktop" -newer "$CLAUDE_HOME/VERSION" 2>/dev/null || true)
  if [ -n "$SUSPICIOUS_AUTOSTART" ]; then
    echo "  WARN  New autostart entries found:"
    echo "$SUSPICIOUS_AUTOSTART" | while read -r f; do echo "         $f"; done
    log_finding "medium" "New autostart entry detected" "$SUSPICIOUS_AUTOSTART"
    WARN=$((WARN + 1))
  else
    echo "  PASS  No suspicious autostart entries"
    PASS=$((PASS + 1))
  fi
fi

# Crontab
CRONTAB_ENTRIES=$(crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$' | grep -v 'opsentry' || true)
if [ -n "$CRONTAB_ENTRIES" ]; then
  ENTRY_COUNT=$(echo "$CRONTAB_ENTRIES" | wc -l | tr -d ' ')
  echo "  INFO  $ENTRY_COUNT crontab entries found (review manually if unexpected)"
else
  echo "  PASS  No non-OpSentry crontab entries"
  PASS=$((PASS + 1))
fi

echo ""

# --- 3. Hook integrity: hash comparison ---
echo "--- Hook Integrity ---"

HOOK_SCRIPTS=(
  "block-sensitive-files.sh" "block-dangerous-commands.sh"
  "block-git-commands.sh" "block-data-exfiltration.sh"
  "block-package-install.sh" "block-scope-escape.sh"
  "block-environment-escape.sh" "block-pii-leakage.sh"
)

for hook in "${HOOK_SCRIPTS[@]}"; do
  INSTALLED="$HOOKS_DIR/$hook"
  SOURCE="$SCRIPT_DIR/claude/hooks/$hook"
  if [ -f "$INSTALLED" ] && [ -f "$SOURCE" ]; then
    INSTALLED_HASH=$(shasum -a 256 "$INSTALLED" | cut -d' ' -f1)
    SOURCE_HASH=$(shasum -a 256 "$SOURCE" | cut -d' ' -f1)
    if [ "$INSTALLED_HASH" = "$SOURCE_HASH" ]; then
      echo "  PASS  $hook — hash matches source"
      PASS=$((PASS + 1))
    else
      echo "  FAIL  $hook — MODIFIED (hash mismatch)"
      log_finding "high" "Hook tampered" "$hook installed=$INSTALLED_HASH source=$SOURCE_HASH"
      FAIL=$((FAIL + 1))
    fi
  elif [ ! -f "$INSTALLED" ]; then
    echo "  FAIL  $hook — MISSING"
    FAIL=$((FAIL + 1))
  fi
done

echo ""

# --- 3b. Configuration baseline integrity ---
# Verifies CLAUDE.md guardrail section + settings.json guardrail subset
# (deny rules + OpSentry hook entries) against the manifest written at
# install time. Catches tampering of the merge-installed config files
# that the per-hook hash check above cannot detect.
echo "--- Configuration Baseline Integrity ---"

if [ -f "$SCRIPT_DIR/baseline.py" ]; then
  BASELINE_OUTPUT=$(python3 "$SCRIPT_DIR/baseline.py" verify \
    --claude-home "$CLAUDE_HOME" \
    --source-dir "$SCRIPT_DIR/claude" 2>&1) || true
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line"
    case "$line" in
      *"  PASS  "*) PASS=$((PASS + 1)) ;;
      *"  WARN  "*) WARN=$((WARN + 1)) ;;
      *"  FAIL  "*)
        FAIL=$((FAIL + 1))
        log_finding "high" "Baseline integrity violation" "$(echo "$line" | tr -d '"\\')"
        ;;
    esac
  done <<< "$BASELINE_OUTPUT"
else
  echo "  WARN  baseline.py not found at $SCRIPT_DIR/baseline.py — skipping baseline check"
  WARN=$((WARN + 1))
fi

echo ""

# --- 4. Block log pattern analysis ---
# Beyond simple counts, runs blocklog_audit.py which scans the log for
# repeat-offender, rapid-burst, multi-hook coverage, exfiltration cluster,
# and self-modification attempt patterns. INFO findings are stats; WARN
# findings indicate suspicious patterns; FAIL findings indicate active
# attack signatures and increment $FAIL.
echo "--- Block Log Pattern Analysis ---"

if [ ! -f "$LOG_FILE" ]; then
  echo "  INFO  No block log found (no blocks recorded yet)"
elif [ -f "$SCRIPT_DIR/blocklog_audit.py" ]; then
  BLOCKLOG_OUTPUT=$(python3 "$SCRIPT_DIR/blocklog_audit.py" analyze \
    --log-file "$LOG_FILE" 2>&1) || true
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line"
    case "$line" in
      *"  PASS  "*) PASS=$((PASS + 1)) ;;
      *"  WARN  "*) WARN=$((WARN + 1)) ;;
      *"  FAIL  "*)
        FAIL=$((FAIL + 1))
        log_finding "high" "Block log attack pattern detected" "$(echo "$line" | tr -d '"\\')"
        ;;
    esac
  done <<< "$BLOCKLOG_OUTPUT"
else
  # Fallback to the legacy basic stats if blocklog_audit.py is unavailable.
  echo "  WARN  blocklog_audit.py not found at $SCRIPT_DIR/blocklog_audit.py — using legacy basic stats"
  WARN=$((WARN + 1))
  TOTAL_BLOCKS=$(wc -l < "$LOG_FILE" | tr -d ' ')
  echo "  INFO  Total blocks logged: $TOTAL_BLOCKS"
fi

echo ""

# --- 5. Immutability check ---
echo "--- Immutability Status ---"

check_immutable() {
  local f="$1"
  local label="$2"
  if [ ! -f "$f" ]; then return; fi
  if [[ "$OSTYPE" == darwin* ]]; then
    if ls -lO "$f" 2>/dev/null | grep -q 'uchg'; then
      echo "  PASS  $label — immutable"
      PASS=$((PASS + 1))
    else
      echo "  WARN  $label — NOT immutable"
      WARN=$((WARN + 1))
    fi
  elif command -v lsattr &>/dev/null; then
    if lsattr "$f" 2>/dev/null | grep -q '^\S*i'; then
      echo "  PASS  $label — immutable"
      PASS=$((PASS + 1))
    else
      echo "  WARN  $label — NOT immutable"
      WARN=$((WARN + 1))
    fi
  fi
}

check_immutable "$CLAUDE_HOME/CLAUDE.md" "CLAUDE.md"
check_immutable "$CLAUDE_HOME/settings.json" "settings.json"
check_immutable "$CLAUDE_HOME/.opsentry-baseline.json" ".opsentry-baseline.json"
for hook in "${HOOK_SCRIPTS[@]}"; do
  check_immutable "$HOOKS_DIR/$hook" "hooks/$hook"
done

echo ""

# --- Summary ---
echo "============================================"
echo "  Patrol Results: $PASS passed, $WARN warnings, $FAIL failed"
echo "============================================"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "  ALERT: Failures detected — guardrail integrity compromised."
  echo "  Run: opsentry install"
  exit 1
elif [ "$WARN" -gt 0 ]; then
  echo "  Warnings detected — review findings above."
  exit 0
else
  echo "  All clear. Guardrails intact and no suspicious activity."
  exit 0
fi

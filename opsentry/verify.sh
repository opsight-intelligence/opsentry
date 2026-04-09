#!/bin/bash
# verify.sh — Checks that all guardrail files are installed and unmodified
# Run from anywhere: /path/to/ai-guardrails/verify.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CLAUDE_HOME="$HOME/.claude"
HOOKS_DIR="$CLAUDE_HOME/hooks"
PASS=0
FAIL=0

echo ""
echo "============================================"
echo "  AI Guardrails Verification"
echo "============================================"
echo ""

check_file() {
  local installed="$1"
  local source="$2"
  local label="$3"

  if [ ! -f "$installed" ]; then
    echo "  FAIL  $label — file missing at $installed"
    FAIL=$((FAIL + 1))
    return
  fi

  if [ -f "$source" ]; then
    if diff -q "$installed" "$source" > /dev/null 2>&1; then
      echo "  PASS  $label — installed and matches source"
      PASS=$((PASS + 1))
    else
      echo "  WARN  $label — installed but MODIFIED (differs from source)"
      FAIL=$((FAIL + 1))
    fi
  else
    echo "  PASS  $label — file exists (no source to compare)"
    PASS=$((PASS + 1))
  fi
}

# Check CLAUDE.md guardrails section is present and matches source
GUARDRAILS_START="<!-- GUARDRAILS START"
GUARDRAILS_END="<!-- GUARDRAILS END -->"

if [ ! -f "$CLAUDE_HOME/CLAUDE.md" ]; then
  echo "  FAIL  CLAUDE.md -- file missing at $CLAUDE_HOME/CLAUDE.md"
  FAIL=$((FAIL + 1))
elif grep -qF "$GUARDRAILS_START" "$CLAUDE_HOME/CLAUDE.md"; then
  # Extract the guardrails section and compare to source
  INSTALLED_SECTION=$(python3 -c "
with open('$CLAUDE_HOME/CLAUDE.md', 'r') as f:
    content = f.read()
start = content.find('$GUARDRAILS_START')
end = content.find('$GUARDRAILS_END') + len('$GUARDRAILS_END')
print(content[start:end])
")
  SOURCE_SECTION=$(cat "$SCRIPT_DIR/claude/CLAUDE.md" | tr -d '\n')
  INSTALLED_TRIMMED=$(echo "$INSTALLED_SECTION" | tr -d '\n')
  if [ "$INSTALLED_TRIMMED" = "$SOURCE_SECTION" ]; then
    echo "  PASS  CLAUDE.md -- guardrails section matches source"
    PASS=$((PASS + 1))
  else
    echo "  WARN  CLAUDE.md -- guardrails section MODIFIED (differs from source)"
    FAIL=$((FAIL + 1))
  fi
else
  echo "  WARN  CLAUDE.md -- file exists but missing guardrails markers (run install.sh to merge)"
  FAIL=$((FAIL + 1))
fi

# Check settings.json has required deny rules
if [ ! -f "$CLAUDE_HOME/settings.json" ]; then
  echo "  FAIL  settings.json -- file missing"
  FAIL=$((FAIL + 1))
else
  MISSING_RULES=$(python3 -c "
import json
with open('$SCRIPT_DIR/claude/settings.json', 'r') as f:
    required = set(json.load(f).get('permissions', {}).get('deny', []))
with open('$CLAUDE_HOME/settings.json', 'r') as f:
    installed = set(json.load(f).get('permissions', {}).get('deny', []))
missing = required - installed
if missing:
    print(f'{len(missing)} missing')
else:
    print('ok')
")
  if [ "$MISSING_RULES" = "ok" ]; then
    echo "  PASS  settings.json -- all guardrail deny rules present"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  settings.json -- $MISSING_RULES guardrail deny rule(s) -- run install.sh"
    FAIL=$((FAIL + 1))
  fi
fi
check_file "$HOOKS_DIR/block-sensitive-files.sh" "$SCRIPT_DIR/claude/hooks/block-sensitive-files.sh" "Hook: block-sensitive-files"
check_file "$HOOKS_DIR/block-dangerous-commands.sh" "$SCRIPT_DIR/claude/hooks/block-dangerous-commands.sh" "Hook: block-dangerous-commands"
check_file "$HOOKS_DIR/block-git-commands.sh" "$SCRIPT_DIR/claude/hooks/block-git-commands.sh" "Hook: block-git-commands"
check_file "$HOOKS_DIR/block-data-exfiltration.sh" "$SCRIPT_DIR/claude/hooks/block-data-exfiltration.sh" "Hook: block-data-exfiltration"
check_file "$HOOKS_DIR/block-package-install.sh" "$SCRIPT_DIR/claude/hooks/block-package-install.sh" "Hook: block-package-install"
check_file "$HOOKS_DIR/block-scope-escape.sh" "$SCRIPT_DIR/claude/hooks/block-scope-escape.sh" "Hook: block-scope-escape"
check_file "$HOOKS_DIR/block-environment-escape.sh" "$SCRIPT_DIR/claude/hooks/block-environment-escape.sh" "Hook: block-environment-escape"
check_file "$HOOKS_DIR/block-pii-leakage.sh" "$SCRIPT_DIR/claude/hooks/block-pii-leakage.sh" "Hook: block-pii-leakage"

# Check hooks are executable
echo ""
for hook in block-sensitive-files.sh block-dangerous-commands.sh block-git-commands.sh block-data-exfiltration.sh block-package-install.sh block-scope-escape.sh block-environment-escape.sh block-pii-leakage.sh; do
  if [ -f "$HOOKS_DIR/$hook" ] && [ -x "$HOOKS_DIR/$hook" ]; then
    echo "  PASS  $hook is executable"
    PASS=$((PASS + 1))
  elif [ -f "$HOOKS_DIR/$hook" ]; then
    echo "  FAIL  $hook exists but is NOT executable (run: chmod +x $HOOKS_DIR/$hook)"
    FAIL=$((FAIL + 1))
  fi
done

# Check hooks are registered in settings.json
echo ""
if [ -f "$CLAUDE_HOME/settings.json" ]; then
  if grep -q "PreToolUse" "$CLAUDE_HOME/settings.json"; then
    echo "  PASS  Hooks are registered in settings.json"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  Hooks are NOT registered in settings.json — re-run install.sh"
    FAIL=$((FAIL + 1))
  fi
fi

# Check jq is available (required by hooks)
echo ""
if command -v jq &> /dev/null; then
  echo "  PASS  jq is installed (required by hook scripts)"
  PASS=$((PASS + 1))
else
  echo "  FAIL  jq is NOT installed — hooks will not work. Install with: brew install jq / apt install jq"
  FAIL=$((FAIL + 1))
fi

# Check slash commands
echo ""
COMMANDS=(security-audit.md code-health.md governance-check.md)
for cmd in "${COMMANDS[@]}"; do
  if [ -f "$CLAUDE_HOME/commands/$cmd" ]; then
    if [ -f "$SCRIPT_DIR/.claude/commands/$cmd" ] && diff -q "$CLAUDE_HOME/commands/$cmd" "$SCRIPT_DIR/.claude/commands/$cmd" > /dev/null 2>&1; then
      echo "  PASS  Command: $cmd -- installed and matches source"
      PASS=$((PASS + 1))
    elif [ -f "$SCRIPT_DIR/.claude/commands/$cmd" ]; then
      echo "  WARN  Command: $cmd -- installed but MODIFIED (differs from source)"
      FAIL=$((FAIL + 1))
    else
      echo "  PASS  Command: $cmd -- file exists (no source to compare)"
      PASS=$((PASS + 1))
    fi
  else
    echo "  FAIL  Command: $cmd -- file missing at $CLAUDE_HOME/commands/$cmd"
    FAIL=$((FAIL + 1))
  fi
done

# Check version
echo ""
REPO_VERSION=""
INSTALLED_VERSION=""
if [ -f "$REPO_ROOT/VERSION" ]; then
  REPO_VERSION=$(tr -d '[:space:]' < "$REPO_ROOT/VERSION")
fi
if [ -f "$CLAUDE_HOME/VERSION" ]; then
  INSTALLED_VERSION=$(tr -d '[:space:]' < "$CLAUDE_HOME/VERSION")
fi

if [ -z "$REPO_VERSION" ]; then
  echo "  WARN  VERSION file not found in repo — skipping version check"
elif [ -z "$INSTALLED_VERSION" ]; then
  echo "  FAIL  VERSION file not installed — run ./install.sh to install version $REPO_VERSION"
  FAIL=$((FAIL + 1))
elif [ "$INSTALLED_VERSION" = "$REPO_VERSION" ]; then
  echo "  PASS  Version $INSTALLED_VERSION is up to date"
  PASS=$((PASS + 1))
else
  echo "  FAIL  Installed version ($INSTALLED_VERSION) does not match repo version ($REPO_VERSION) — run ./update.sh"
  FAIL=$((FAIL + 1))
fi

# Summary
echo ""
echo "============================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "============================================"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "  Some checks failed. Run ./install.sh to fix."
  exit 1
else
  echo "  All checks passed. Guardrails are properly installed."
  exit 0
fi

#!/bin/bash
# install.sh -- Installs AI guardrails for Claude Code using merge-based strategy.
# Preserves employee custom CLAUDE.md content, settings.json permissions, and hooks.
# Run from the repo root: ./ai-guardrails/install.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CLAUDE_HOME="$HOME/.claude"
HOOKS_DIR="$CLAUDE_HOME/hooks"

GUARDRAILS_START="<!-- GUARDRAILS START — DO NOT EDIT THIS SECTION -->"
GUARDRAILS_END="<!-- GUARDRAILS END -->"

echo ""
echo "============================================"
echo "  AI Guardrails Installer for Claude Code"
echo "============================================"
echo ""

# --- Step 1: Create directories ---
echo "[1/7] Creating directories..."
mkdir -p "$CLAUDE_HOME"
mkdir -p "$HOOKS_DIR"
mkdir -p "$CLAUDE_HOME/commands"

# --- Step 1b: Run config generator if guardrails.yaml exists ---
if [ -f "$REPO_ROOT/guardrails.yaml" ]; then
  echo "       Found guardrails.yaml — running config generator..."
  if command -v python3 &> /dev/null; then
    python3 "$REPO_ROOT/config/generate.py" "$REPO_ROOT/guardrails.yaml" --output-dir "$SCRIPT_DIR/claude" 2>&1 | sed 's/^/       /'
    echo "       Config generated successfully."
  else
    echo "       WARNING: python3 not found -- skipping config generation. Install the generated files manually."
  fi
fi

# --- Step 2: Install VERSION ---
echo "[2/7] Installing VERSION..."
if [ -f "$REPO_ROOT/VERSION" ]; then
  cp "$REPO_ROOT/VERSION" "$CLAUDE_HOME/VERSION"
  echo "       Installed: $CLAUDE_HOME/VERSION ($(cat "$REPO_ROOT/VERSION"))"
else
  echo "       WARNING: VERSION file not found at $REPO_ROOT/VERSION -- skipping"
fi

# --- Step 3: Merge CLAUDE.md (preserve employee content outside markers) ---
echo "[3/7] Merging CLAUDE.md..."
GUARDRAILS_CONTENT="$SCRIPT_DIR/claude/CLAUDE.md"

if [ -f "$CLAUDE_HOME/CLAUDE.md" ]; then
  # Check if existing file has guardrails markers
  if grep -qF "$GUARDRAILS_START" "$CLAUDE_HOME/CLAUDE.md"; then
    # Replace content between markers, keep everything else
    python3 -c "
import sys

marker_start = '$GUARDRAILS_START'
marker_end = '$GUARDRAILS_END'

with open('$CLAUDE_HOME/CLAUDE.md', 'r') as f:
    existing = f.read()

with open('$GUARDRAILS_CONTENT', 'r') as f:
    guardrails = f.read()

start_idx = existing.find(marker_start)
end_idx = existing.find(marker_end)

if start_idx == -1 or end_idx == -1:
    print('ERROR: Malformed markers in existing CLAUDE.md', file=sys.stderr)
    sys.exit(1)

end_idx += len(marker_end)

merged = existing[:start_idx] + guardrails + existing[end_idx:]

with open('$CLAUDE_HOME/CLAUDE.md', 'w') as f:
    f.write(merged)
"
    echo "       Merged: guardrails section updated, employee content preserved"
  else
    # No markers found -- existing file is from old installer or fully custom.
    # Prepend guardrails content, keep existing content below.
    cp "$CLAUDE_HOME/CLAUDE.md" "$CLAUDE_HOME/CLAUDE.md.backup"
    echo "       Existing CLAUDE.md has no guardrails markers -- backing up to CLAUDE.md.backup"
    EXISTING_CONTENT=$(cat "$CLAUDE_HOME/CLAUDE.md")
    cat "$GUARDRAILS_CONTENT" > "$CLAUDE_HOME/CLAUDE.md"
    printf "\n\n%s" "$EXISTING_CONTENT" >> "$CLAUDE_HOME/CLAUDE.md"
    echo "       Merged: guardrails prepended, original content preserved below"
  fi
else
  cp "$GUARDRAILS_CONTENT" "$CLAUDE_HOME/CLAUDE.md"
  echo "       Installed: $CLAUDE_HOME/CLAUDE.md (fresh install)"
fi

# --- Step 4: Merge settings.json (union deny rules, preserve custom permissions) ---
echo "[4/7] Merging settings.json..."

GUARDRAILS_SETTINGS="$SCRIPT_DIR/claude/settings.json"

if [ -f "$CLAUDE_HOME/settings.json" ]; then
  python3 -c "
import json, sys

with open('$GUARDRAILS_SETTINGS', 'r') as f:
    guardrails = json.load(f)

with open('$CLAUDE_HOME/settings.json', 'r') as f:
    existing = json.load(f)

# Merge permissions.deny as a union (guardrails rules + employee custom rules)
guardrail_deny = guardrails.get('permissions', {}).get('deny', [])
existing_deny = existing.get('permissions', {}).get('deny', [])

merged_deny = list(guardrail_deny)
for rule in existing_deny:
    if rule not in merged_deny:
        merged_deny.append(rule)

if 'permissions' not in existing:
    existing['permissions'] = {}
existing['permissions']['deny'] = merged_deny

# Preserve any other permission keys (allow, etc.) the employee may have set
for key in guardrails.get('permissions', {}):
    if key != 'deny' and key not in existing.get('permissions', {}):
        existing['permissions'][key] = guardrails['permissions'][key]

with open('$CLAUDE_HOME/settings.json', 'w') as f:
    json.dump(existing, f, indent=2)

added = len(merged_deny) - len(existing_deny)
if added > 0:
    print(f'       Merged: {added} new deny rule(s) added, {len(existing_deny)} existing rule(s) preserved')
else:
    print(f'       Merged: all {len(guardrail_deny)} guardrail deny rules already present, {len(merged_deny) - len(guardrail_deny)} custom rule(s) preserved')
"
else
  cp "$GUARDRAILS_SETTINGS" "$CLAUDE_HOME/settings.json"
  echo "       Installed: $CLAUDE_HOME/settings.json (fresh install)"
fi

# --- Step 5: Install hook scripts ---
echo "[5/7] Installing hook scripts..."
HOOK_SCRIPTS=(
  block-sensitive-files.sh
  block-dangerous-commands.sh
  block-git-commands.sh
  block-data-exfiltration.sh
  block-package-install.sh
  block-scope-escape.sh
  block-environment-escape.sh
  block-pii-leakage.sh
)
for hook in "${HOOK_SCRIPTS[@]}"; do
  cp "$SCRIPT_DIR/claude/hooks/$hook" "$HOOKS_DIR/"
  chmod +x "$HOOKS_DIR/$hook"
done
echo "       Installed ${#HOOK_SCRIPTS[@]} hook scripts to: $HOOKS_DIR/"

# --- Step 6: Register hooks in settings.json (append, don't replace) ---
echo "[6/7] Registering hooks in settings.json..."

python3 -c "
import json

settings_path = '$CLAUDE_HOME/settings.json'
hooks_dir = '$HOOKS_DIR'

with open(settings_path, 'r') as f:
    settings = json.load(f)

# Define the guardrail hook entries we need registered
guardrail_hooks = {
    'Read': [
        {'type': 'command', 'command': f'{hooks_dir}/block-sensitive-files.sh'},
        {'type': 'command', 'command': f'{hooks_dir}/block-scope-escape.sh'}
    ],
    'Write': [
        {'type': 'command', 'command': f'{hooks_dir}/block-scope-escape.sh'},
        {'type': 'command', 'command': f'{hooks_dir}/block-pii-leakage.sh'}
    ],
    'Edit': [
        {'type': 'command', 'command': f'{hooks_dir}/block-scope-escape.sh'},
        {'type': 'command', 'command': f'{hooks_dir}/block-pii-leakage.sh'}
    ],
    'Bash': [
        {'type': 'command', 'command': f'{hooks_dir}/block-sensitive-files.sh'},
        {'type': 'command', 'command': f'{hooks_dir}/block-dangerous-commands.sh'},
        {'type': 'command', 'command': f'{hooks_dir}/block-git-commands.sh'},
        {'type': 'command', 'command': f'{hooks_dir}/block-data-exfiltration.sh'},
        {'type': 'command', 'command': f'{hooks_dir}/block-package-install.sh'},
        {'type': 'command', 'command': f'{hooks_dir}/block-scope-escape.sh'},
        {'type': 'command', 'command': f'{hooks_dir}/block-environment-escape.sh'},
        {'type': 'command', 'command': f'{hooks_dir}/block-pii-leakage.sh'}
    ]
}

# Guardrail hook commands for identification during merge
guardrail_commands = set()
for hook_list in guardrail_hooks.values():
    for h in hook_list:
        guardrail_commands.add(h['command'])

existing_pre = settings.get('hooks', {}).get('PreToolUse', [])

# Index existing matchers and their non-guardrail hooks
merged_pre = []
seen_matchers = set()

for entry in existing_pre:
    matcher = entry.get('matcher', '')
    if matcher in guardrail_hooks:
        # Keep only non-guardrail hooks from this matcher
        custom_hooks = [h for h in entry.get('hooks', []) if h.get('command', '') not in guardrail_commands]
        # Prepend guardrail hooks, then custom hooks
        merged_entry = {
            'matcher': matcher,
            'hooks': guardrail_hooks[matcher] + custom_hooks
        }
        merged_pre.append(merged_entry)
        seen_matchers.add(matcher)
    else:
        # Employee custom matcher -- keep as-is
        merged_pre.append(entry)
        seen_matchers.add(matcher)

# Add guardrail matchers that did not exist yet
for matcher, hooks_list in guardrail_hooks.items():
    if matcher not in seen_matchers:
        merged_pre.append({'matcher': matcher, 'hooks': hooks_list})

if 'hooks' not in settings:
    settings['hooks'] = {}
settings['hooks']['PreToolUse'] = merged_pre

with open(settings_path, 'w') as f:
    json.dump(settings, f, indent=2)
print('       Hooks registered (employee custom hooks preserved).')
"

# --- Step 7: Install slash commands ---
echo "[7/7] Installing slash commands..."
cp "$SCRIPT_DIR/.claude/commands/security-audit.md" "$CLAUDE_HOME/commands/"
cp "$SCRIPT_DIR/.claude/commands/code-health.md" "$CLAUDE_HOME/commands/"
cp "$SCRIPT_DIR/.claude/commands/governance-check.md" "$CLAUDE_HOME/commands/"
echo "       Installed 3 slash commands to: $CLAUDE_HOME/commands/"

echo ""
echo "============================================"
echo "  Installation complete!"
echo "============================================"
echo ""
echo "  Installed files:"
echo "    - $CLAUDE_HOME/VERSION"
echo "    - $CLAUDE_HOME/CLAUDE.md (merged)"
echo "    - $CLAUDE_HOME/settings.json (merged)"
for hook in "${HOOK_SCRIPTS[@]}"; do
  echo "    - $HOOKS_DIR/$hook"
done
echo "    - $CLAUDE_HOME/commands/security-audit.md"
echo "    - $CLAUDE_HOME/commands/code-health.md"
echo "    - $CLAUDE_HOME/commands/governance-check.md"
echo ""
echo "  Slash commands available in Claude Code:"
echo "    /security-audit   -- Scan for vulnerabilities and secrets"
echo "    /code-health      -- Check code quality and standards"
echo "    /governance-check -- Verify guardrail compliance"
echo ""
echo "  Restart Claude Code for changes to take effect."
echo ""
echo "  To verify installation, run: ./ai-guardrails/verify.sh"
echo ""

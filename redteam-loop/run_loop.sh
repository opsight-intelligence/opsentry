#!/usr/bin/env bash
# Red-team / blue-team hardening loop for opsentry hooks.
# - Generates novel attacks via headless Claude (attacker role)
# - Evaluates them against current hooks
# - Asks Claude (defender role) for a unified diff patching the unblocked ones
# - Applies the patch to a WORKDIR COPY (never touches repo hooks)
# - Re-runs existing test.sh + a held-out attack set
# - Stops early when a round finds zero new successful attacks
# NEVER runs git commands. Review rounds/ and SUMMARY.md, apply patches manually.

set -euo pipefail

ROUNDS_MAX=3
ATTACKS_PER_ROUND=10
HELDOUT_PER_ROUND=2

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_HOOKS="$REPO_DIR/opsentry/claude/hooks"
SRC_TESTS="$REPO_DIR/opsentry/test.sh"
WORKDIR="$SCRIPT_DIR/workdir"
ROUNDS_DIR="$SCRIPT_DIR/rounds"
PROMPTS_DIR="$SCRIPT_DIR/prompts"

command -v claude >/dev/null || { echo "claude CLI not on PATH"; exit 1; }
command -v jq >/dev/null     || { echo "jq required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }

# Fresh workdir; leave rounds/ cumulative across runs (numbered subdirs)
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/claude" "$ROUNDS_DIR"
cp -R "$SRC_HOOKS" "$WORKDIR/claude/hooks"
sed "s|HOOKS_DIR=\"\$SCRIPT_DIR/claude/hooks\"|HOOKS_DIR=\"$WORKDIR/claude/hooks\"|" \
    "$SRC_TESTS" > "$WORKDIR/test.sh"
chmod +x "$WORKDIR/test.sh"

# Unique session directory so re-runs don't overwrite prior findings
SESSION="$(date +%Y%m%d-%H%M%S)"
SDIR="$ROUNDS_DIR/$SESSION"
mkdir -p "$SDIR"

prior_attacks="[]"
prev_unblocked=-1

for round in $(seq 1 "$ROUNDS_MAX"); do
  echo "=== Round $round ==="
  RDIR="$SDIR/round-$round"
  mkdir -p "$RDIR"

  # --- Attacker ---
  {
    cat "$PROMPTS_DIR/attacker.md"
    printf '\n\nROUND_NUMBER: %d\nATTACKS_REQUESTED: %d\n\nPRIOR_ATTACKS_JSON:\n%s\n\nOutput ONLY the JSON array.\n' \
      "$round" "$ATTACKS_PER_ROUND" "$prior_attacks"
  } | claude -p --output-format text > "$RDIR/attacker_raw.txt"

  # Extract the first JSON array from attacker output
  python3 - "$RDIR/attacker_raw.txt" "$RDIR/attacks.json" <<'PY'
import json, re, sys
raw = open(sys.argv[1]).read()
m = re.search(r'\[\s*(?:\{.*?\}\s*,?\s*)+\]', raw, re.S)
out = []
if m:
    try: out = json.loads(m.group(0))
    except Exception: out = []
json.dump(out, open(sys.argv[2], 'w'), indent=2)
PY
  total=$(jq 'length' "$RDIR/attacks.json")
  echo "  Attacker produced $total attacks"
  if [ "$total" -lt 3 ]; then
    echo "  Attacker output unusable; aborting round."
    break
  fi

  heldout=$(( total < HELDOUT_PER_ROUND ? 0 : HELDOUT_PER_ROUND ))
  jq ".[0:$((total-heldout))]" "$RDIR/attacks.json" > "$RDIR/training.json"
  jq ".[$((total-heldout)):]"  "$RDIR/attacks.json" > "$RDIR/heldout.json"

  # --- Pre-patch eval ---
  bash "$SCRIPT_DIR/harness/eval_attacks.sh" "$RDIR/training.json" "$WORKDIR/claude/hooks" > "$RDIR/train_pre.json"
  bash "$SCRIPT_DIR/harness/eval_attacks.sh" "$RDIR/heldout.json"  "$WORKDIR/claude/hooks" > "$RDIR/heldout_pre.json"
  unblocked=$(jq '[.[] | select(.blocked==false)] | length' "$RDIR/train_pre.json")
  echo "  Unblocked training attacks: $unblocked / $(jq length "$RDIR/training.json")"

  # Plateau check
  if [ "$unblocked" -eq 0 ] && [ "$prev_unblocked" -eq 0 ]; then
    echo "  Two consecutive rounds with zero new successes. Stopping."
    break
  fi

  if [ "$unblocked" -gt 0 ]; then
    # --- Defender ---
    HOOK_SRC_FILE="$RDIR/hook_sources.txt"
    : > "$HOOK_SRC_FILE"
    for h in "$WORKDIR/claude/hooks"/*.sh; do
      printf '\n--- FILE: %s ---\n' "$(basename "$h")" >> "$HOOK_SRC_FILE"
      cat "$h" >> "$HOOK_SRC_FILE"
    done

    {
      cat "$PROMPTS_DIR/defender.md"
      echo ""
      echo "CURRENT_HOOKS:"
      cat "$HOOK_SRC_FILE"
      echo ""
      echo "ATTACKS_TO_BLOCK (currently bypass the hooks):"
      jq '[.[] | select(.blocked==false) | .attack]' "$RDIR/train_pre.json"
    } | claude -p --output-format text > "$RDIR/defender_raw.txt"

    # Split output: everything before ==TESTS== is the diff, after is new tests
    awk '/^==TESTS==[[:space:]]*$/{exit} {print}' "$RDIR/defender_raw.txt" > "$RDIR/patch.diff"
    awk 'f{print} /^==TESTS==[[:space:]]*$/{f=1}' "$RDIR/defender_raw.txt" > "$RDIR/new_tests.sh"

    # Strip any accidental markdown fences
    sed -i '' -e '/^```/d' "$RDIR/patch.diff" 2>/dev/null || sed -i -e '/^```/d' "$RDIR/patch.diff"

    if [ ! -s "$RDIR/patch.diff" ]; then
      echo "  Defender returned no diff; skipping patch step."
    elif ! (cd "$WORKDIR/claude/hooks" && patch -p0 --dry-run < "$RDIR/patch.diff" >/dev/null 2>&1); then
      echo "  Patch does not apply cleanly; saved to $RDIR/patch.diff for inspection."
    else
      (cd "$WORKDIR/claude/hooks" && patch -p0 < "$RDIR/patch.diff" >/dev/null)
      echo "  Patch applied to workdir."
    fi
  fi

  # --- Post-patch eval (always runs; shows whether defender helped) ---
  bash "$SCRIPT_DIR/harness/eval_attacks.sh" "$RDIR/training.json" "$WORKDIR/claude/hooks" > "$RDIR/train_post.json"
  bash "$SCRIPT_DIR/harness/eval_attacks.sh" "$RDIR/heldout.json"  "$WORKDIR/claude/hooks" > "$RDIR/heldout_post.json"
  bash "$WORKDIR/test.sh" > "$RDIR/tests.txt" 2>&1 || true

  tp=$(grep -cE "^[[:space:]]+PASS " "$RDIR/tests.txt" || true); tp=${tp:-0}
  tf=$(grep -cE "^[[:space:]]+FAIL " "$RDIR/tests.txt" || true); tf=${tf:-0}
  tb=$(jq '[.[] | select(.blocked==true)] | length' "$RDIR/train_post.json")
  tt=$(jq 'length' "$RDIR/training.json")
  hb=$(jq '[.[] | select(.blocked==true)] | length' "$RDIR/heldout_post.json")
  ht=$(jq 'length' "$RDIR/heldout.json")
  echo "  Post-patch: existing_tests=${tp}P/${tf}F  training_blocked=${tb}/${tt}  heldout_blocked=${hb}/${ht}"

  prev_unblocked=$unblocked
  prior_attacks=$(jq -s 'add' "$SDIR"/round-*/attacks.json)
done

# --- Summary ---
{
  echo "# Red-team loop — session $SESSION"
  echo ""
  echo "Target: $SRC_HOOKS"
  echo "Workdir (patched copy, for inspection): $WORKDIR"
  echo ""
  echo "| Round | Attacks | Unblocked pre | Training blocked post | Heldout blocked | Existing tests P/F |"
  echo "|-------|---------|---------------|-----------------------|-----------------|--------------------|"
  for rd in "$SDIR"/round-*; do
    [ -d "$rd" ] || continue
    n=$(basename "$rd")
    a=$(jq length "$rd/attacks.json" 2>/dev/null || echo 0)
    u=$(jq '[.[] | select(.blocked==false)] | length' "$rd/train_pre.json" 2>/dev/null || echo -)
    tb=$(jq '[.[] | select(.blocked==true)] | length' "$rd/train_post.json" 2>/dev/null || echo -)
    tt=$(jq length "$rd/training.json" 2>/dev/null || echo -)
    hb=$(jq '[.[] | select(.blocked==true)] | length' "$rd/heldout_post.json" 2>/dev/null || echo -)
    ht=$(jq length "$rd/heldout.json" 2>/dev/null || echo -)
    tp=$(grep -cE "^[[:space:]]+PASS " "$rd/tests.txt" 2>/dev/null || echo -)
    tf=$(grep -cE "^[[:space:]]+FAIL " "$rd/tests.txt" 2>/dev/null || echo -)
    echo "| $n | $a | $u | $tb/$tt | $hb/$ht | $tp/$tf |"
  done
  echo ""
  echo "## Review checklist"
  echo "- Inspect each \`round-*/patch.diff\` before applying"
  echo "- \`heldout_blocked\` < \`training_blocked\` = overfit signal"
  echo "- Existing tests must still be 169P / 0F"
  echo ""
  echo "## Apply a round's patch manually"
  echo ""
  echo '```'
  echo "cd $SRC_HOOKS"
  echo "patch -p0 < $SDIR/round-N/patch.diff"
  echo "cat $SDIR/round-N/new_tests.sh  # review, then append relevant lines to opsentry/test.sh"
  echo "bash $SRC_TESTS"
  echo '```'
} > "$SDIR/SUMMARY.md"

echo ""
echo "Done. Review: $SDIR/SUMMARY.md"

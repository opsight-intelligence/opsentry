#!/bin/bash
# update.sh — Pulls the latest guardrails and re-installs
# Run this from the ai-guardrails repo root: ./update.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "Updating AI Guardrails..."
echo ""

# Pull latest from repo
echo "[1/2] Pulling latest changes..."
git -C "$SCRIPT_DIR" pull

# Re-run installer
echo "[2/2] Re-installing..."
bash "$SCRIPT_DIR/install.sh"

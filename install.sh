#!/bin/bash
# Shortcut: delegates to the main installer.
exec "$(dirname "$0")/agentguard/install.sh" "$@"

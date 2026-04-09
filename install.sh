#!/bin/bash
# Shortcut: delegates to the main installer.
exec "$(dirname "$0")/opsentry/install.sh" "$@"

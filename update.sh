#!/bin/bash
# Shortcut: delegates to the main updater.
exec "$(dirname "$0")/opsentry/update.sh" "$@"

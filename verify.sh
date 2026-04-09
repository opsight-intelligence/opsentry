#!/bin/bash
# Shortcut: delegates to the main verifier.
exec "$(dirname "$0")/opsentry/verify.sh" "$@"

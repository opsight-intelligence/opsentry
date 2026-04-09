#!/bin/bash
# Shortcut: delegates to the test runner.
exec "$(dirname "$0")/opsentry/test.sh" "$@"

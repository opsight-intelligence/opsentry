#!/bin/bash
# Shortcut: delegates to the test runner.
exec "$(dirname "$0")/agentguard/test.sh" "$@"

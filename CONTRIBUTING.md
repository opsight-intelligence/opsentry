# Contributing to OpSentry

Thanks for your interest in contributing to OpSentry.

## How to Contribute

### Reporting Bugs

Open a [GitHub issue](https://github.com/opsight-intelligence/opsentry/issues) with:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Your OS and shell (bash/zsh)

### Suggesting New Patterns

If you find a dangerous pattern that OpSentry should block, open an issue with:
- The pattern (command, file path, or code snippet)
- Why it should be blocked
- Which hook script should handle it

### Submitting Pull Requests

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/block-new-pattern`)
3. Make your changes
4. Run the test suite: `./test.sh`
5. Ensure all 88+ tests pass
6. Submit a PR against `main`

### Code Style

- Hook scripts use `set -euo pipefail`
- Use `jq` for JSON parsing in hooks
- Exit code `0` = allow, exit code `2` = block
- Blocked messages go to stderr
- Every hook must log blocks to `~/.claude/guardrail-blocks.log`

### Adding a New Hook

1. Create the script in `opsentry/claude/hooks/`
2. Follow the existing pattern: parse JSON stdin, check patterns, exit 0 or 2
3. Add the `log_block` function for incident logging
4. Add tests to `test.sh`
5. Document the hook in `README.md`

## Code of Conduct

Be respectful, constructive, and professional. We are building security tooling — precision and clarity matter more than speed.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

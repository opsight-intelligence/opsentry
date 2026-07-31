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
2. Create a feature branch off `develop` (`git checkout -b feature/block-new-pattern develop`)
3. Make your changes
4. Run the test suite: `./test.sh`
5. Ensure all 88+ tests pass
6. Bump `VERSION`, add a `CHANGELOG.md` entry, and update the docs (see below)
7. Submit a PR against `develop`

## Branching model (Git Flow)

| Branch | Role |
|--------|------|
| `main` | Production. Only ever updated by merging `release/*` or `hotfix/*`. |
| `develop` | Integration branch. Default target for PRs. |
| `feature/<name>` | Branched from `develop`, merged back into `develop`. |
| `bugfix/<name>` | Non-urgent fixes. Branched from `develop`. |
| `release/<version>` | Cut from `develop`, merged into `main` **and** back into `develop`. |
| `hotfix/<version>` | Cut from `main` for urgent fixes, merged into `main` **and** `develop`. |

Never commit directly to `main` or `develop`.

## Versioning

Semantic Versioning (`MAJOR.MINOR.PATCH`), tracked in the `VERSION` file at the repo root.

- **MAJOR** — breaking changes to hook behavior, exit codes, or the installed config surface
- **MINOR** — new hooks, new blocked patterns, backwards-compatible additions
- **PATCH** — bug fixes, false-positive corrections, documentation, refactors

Every commit bumps `VERSION` and stages it alongside the change. Releases that land on
`main` are tagged `v<version>`.

## Required with every change

A change is not complete until all four land in the same commit:

1. **Code** — the change itself, with tests in `test.sh`
2. **`VERSION`** — bumped per SemVer
3. **`CHANGELOG.md`** — entry under `## [Unreleased]`, in the appropriate
   `### Added` / `### Changed` / `### Deprecated` / `### Removed` / `### Fixed` /
   `### Security` subsection
4. **Docs** — `README.md` for any new or changed hook, `docs/quickstart.md` for anything
   affecting installation or first-run behavior, and migration notes for breaking changes

If a change genuinely affects no documentation, say so in the PR rather than skipping silently.

## Commit messages

Conventional Commits, with the resulting version in brackets:

```
type(scope): subject [vX.Y.Z]
```

`type` is one of `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`,
`build`, `ci`. Subject is imperative and under 72 characters. Use the body to explain
why, not what.

Examples:

- `feat(hooks): block dlopen with variable paths [v1.9.0]`
- `fix(block-scope-escape): stop false-positive on ~/Library [v1.8.2]`

## Releasing

1. Cut `release/<version>` from `develop`
2. Roll `## [Unreleased]` into a `## [<version>] - <YYYY-MM-DD>` section
3. Open a PR into `main`, merge, then tag `v<version>`
4. Merge `main` back into `develop`
5. Delete the release branch locally and on the remote, and close any PRs the release
   supersedes

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

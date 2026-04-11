# OpSentry

> Claude Code has full access to your file system and shell.
> It can read your `.env` files, run `rm -rf`, execute
> `git push --force`, and `curl` data to external servers.
> OpSentry stops it — deterministically, not just advisorily.

The only guardrails framework built around Claude Code's
native PreToolUse hook architecture. Three enforcement layers.
Every tool call intercepted before execution.

Built by [Opsight Intelligence](https://opsightintel.com).

---

## Why Claude Code is different

Most AI coding assistants can only be guided with rules
they may or may not follow.

Claude Code has a `PreToolUse` hook architecture — every tool
call is intercepted before execution, inspected by bash scripts,
and blocked with exit code 2 if it matches a dangerous pattern.

This makes true deterministic enforcement possible.
OpSentry is built specifically for this architecture.

---

## Install in 2 minutes

**pip (recommended)**

    pip install opsentry
    opsentry install

**Homebrew**

    brew tap opsight-intelligence/opsentry
    brew install opsentry
    opsentry install

**Git clone**

    git clone https://github.com/opsight-intelligence/opsentry
    cd opsentry
    ./install.sh

**GitHub Action (CI/CD)**

    uses: opsight-intelligence/opsentry-action@v1

Restart Claude Code after install. That's it.

**Prerequisites:** jq must be installed.
- macOS: brew install jq
- Ubuntu/Debian: sudo apt install jq

---

## Three enforcement layers

**Layer 1 — CLAUDE.md (behavioral)**
18 security rules Claude Code reads at session start.
Advisory — influences behavior but not enforced alone.

**Layer 2 — settings.json (permission denials)**
70+ hard deny rules at the platform level.
Blocks file access and commands before hooks run.
Cannot be overridden by the AI.

**Layer 3 — Hook scripts (deterministic)**
8 bash scripts intercepting every tool call.
Pattern-matched blocking with exit code 2.
Context-aware — blocks base64 .env but allows base64 image.png
Full incident logging to ~/.claude/opsentry-blocks.log

Even if the AI ignores advisory rules, layers 2 and 3 block
prohibited actions.

---

## What gets blocked

| Category | Examples |
|---|---|
| Sensitive files | .env, credentials, SSL certs, SSH keys, cloud configs |
| Dangerous commands | rm -rf, sudo, chmod 777, DROP TABLE, pipe-to-shell |
| Git operations | All git commands — agent writes them as text for you to run |
| Data exfiltration | curl/wget uploads, base64 of secrets, netcat channels |
| Untrusted packages | pip/npm from git URLs, custom registries |
| Environment escape | ssh, docker run/exec, terraform apply/destroy |
| PII in code | SSNs, credit card numbers, Korean RRNs |

---

## Verify installation

./verify.sh

Checks all hooks are present, unmodified, executable,
and registered correctly.

---

## Update

cd opsentry && ./update.sh

Pulls latest rules and re-installs. Merge strategy preserves
any personal customisations.

---

## Test suite

./test.sh

168 automated tests (101 functional + 67 adversarial red-team)
covering blocked and allowed cases for every hook, including
project-local `.claude/` directories, `~/Library/` on macOS,
`/var/folders/`, and symlink-based bypass attempts.

---

## Red team tested

We attacked our own framework with 8 adversarial attack classes
and documented every finding, patch, and residual risk.

Read the full report: [docs/red-team-log.md](docs/red-team-log.md)

| Attack | Vector | Status |
|---|---|---|
| 1 | Indirect file read via interpreters | Patched |
| 2 | Write tool content blind spot | Patched |
| 3 | Prompt injection + guardrail self-destruction | Patched |
| 4 | Edit tool salami attack (cross-file composition) | Patched (residual at CI layer) |
| 5 | Environment variable poisoning | Patched |
| 6 | Symlink redirection | Patched |
| 7 | Persistence and delayed execution | Patched |
| 8 | Hook starvation via resource exhaustion | Patched |

No other AI agent security tool publishes adversarial testing evidence.

---

## What about Copilot, Cursor, Windsurf?

Full three-layer enforcement requires Claude Code's
PreToolUse hook architecture — currently unique to Claude Code.

For teams using other AI coding assistants:
OpSentry's advisory policy layer (CLAUDE.md behavioral rules
and permission documentation) is adaptable as a starting point.

Full deterministic enforcement requires Claude Code.

---

## Community vs Pro vs Enterprise

| Feature | Community | Pro | Enterprise |
|---|---|---|---|
| 8 hook scripts | ✓ | ✓ | ✓ |
| 18 behavioral rules | ✓ | ✓ | ✓ |
| 70+ permission denials | ✓ | ✓ | ✓ |
| 3 slash commands | ✓ | ✓ | ✓ |
| Incident logging | ✓ | ✓ | ✓ |
| 168 automated tests | ✓ | ✓ | ✓ |
| CI/CD agents (GitHub Actions) | | ✓ | ✓ |
| LLM-powered code review (BYOK) | | ✓ | ✓ |
| Auto-fix on PR | | ✓ | ✓ |
| Vertical config packs | | ✓ | ✓ |
| Multi-repo deployment | | | ✓ |
| Centralized incident dashboard | | | ✓ |
| Compliance reporting (ISO 27001, SOC2) | | | ✓ |
| Custom vertical development | | | ✓ |

Contact utku@opsightintel.com for Pro and Enterprise.

---

## Questions or issues

Open an issue or contact utku@opsightintel.com

Built by [Opsight Intelligence](https://opsightintel.com) —
Telegram threat intelligence and AI security for
financial institutions.

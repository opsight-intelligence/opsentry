# OpSentry

> Three layers of defense for AI coding agents —
> **detect**, **prevent**, and **make dangerous actions
> architecturally impossible**.

Competitors match patterns and lose the arms race.
OpSentry makes entire attack classes impossible.

Runtime guardrails. CI/CD composition analysis.
OS-level sandbox profiles. From a single YAML config.

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

## Three layers of defense

**Layer 1 — Detect (Runtime Guardrails)**
8 hook scripts + 18 behavioral rules + 70+ permission denials.
Pre-execution pattern matching blocks known attack vectors
before they run. 203 tests. Battle-tested against 8 red team attacks.

**Layer 2 — Prevent (CI/CD Analysis)**
Cross-file AST composition analysis at PR time.
Import-graph-aware — catches exfiltration patterns assembled
across multiple files. Auto-fix and merge gating.

**Layer 3 — Make Impossible (Sandbox Profiles)**
Generated platform-specific sandbox configs that deny
dangerous actions at the OS kernel level.
macOS (sandbox-exec), Linux (bubblewrap), Docker.

```bash
opsentry sandbox generate --platform all
```

Each layer uses a different detection strategy. An attacker
must defeat all three — not just one.

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

203 automated tests: 168 hook tests (101 functional +
67 adversarial red-team) plus 42 cross-file composition
tests plus 23 network exposure tests.

---

## Red team tested — and reproducible

We attacked our own framework with 8 adversarial attack classes, patched every
finding, and documented the residual risk for each. **The adversarial loop is
shipped in this repository — you can rerun it yourself.**

Read the full report: [docs/red-team-log.md](docs/red-team-log.md)

### Published attack evidence

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

### Run the loop yourself

[`redteam-loop/`](redteam-loop/) is a review-gated attacker/defender harness
that re-hardens the hooks against novel attacks. Each round:

1. **Attacker** (headless Claude) generates 10 novel PreToolUse payloads.
2. Attacks are split 80/20 into training and **held-out** sets — the defender
   never sees the held-out attacks, so regex overfit is detectable.
3. Each attack runs against every hook in an isolated workdir copy.
4. **Defender** (headless Claude) receives the failing attacks plus hook
   sources and returns a unified diff.
5. The patch is applied to the workdir; `test.sh` must stay green; training
   and held-out attacks are re-run.
6. Stops after 3 rounds or two consecutive zero-bypass rounds.

```bash
bash redteam-loop/run_loop.sh
```

**Safety properties:** never modifies your live hooks, never runs git, never
executes the defender patch against the real framework. You review and apply.

Requirements: `claude` CLI on PATH (headless mode), `jq`, `python3`, `patch`.
See [redteam-loop/README.md](redteam-loop/README.md) for details.

No other AI agent security tool publishes adversarial testing evidence — or
ships the tooling for you to reproduce and extend it.

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
| 203 automated tests | ✓ | ✓ | ✓ |
| CI/CD agents (GitHub Actions) | | ✓ | ✓ |
| Cross-file exfiltration detection (AST) | | ✓ | ✓ |
| **Sandbox profile generator** | | **✓** | **✓** |
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

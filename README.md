# OpSight AgentGuard

Security guardrails for AI coding agents. Three-layer enforcement (behavioral rules, permission denials, deterministic hooks) that prevents AI agents from accessing secrets, executing dangerous commands, or leaking sensitive data.

Built by [OpSight Intelligence](https://github.com/opsight-intelligence).

## Quick Start

```bash
git clone https://github.com/opsight-intelligence/agentguard.git
cd agentguard
./install.sh
```

Restart Claude Code after installation.

## What Gets Installed

| File | Location | Purpose |
|------|----------|---------|
| `CLAUDE.md` | `~/.claude/CLAUDE.md` | Behavioral rules Claude Code follows every session |
| `settings.json` | `~/.claude/settings.json` | Hard deny rules for sensitive file access and dangerous commands |
| `block-sensitive-files.sh` | `~/.claude/hooks/` | Blocks reading .env, credentials, secrets, certificates |
| `block-dangerous-commands.sh` | `~/.claude/hooks/` | Blocks rm -rf, sudo, chmod 777, DROP TABLE, etc. |
| `block-git-commands.sh` | `~/.claude/hooks/` | Blocks all git command execution |
| `block-data-exfiltration.sh` | `~/.claude/hooks/` | Blocks curl/wget uploads, base64 of secrets, /tmp writes, netcat |
| `block-package-install.sh` | `~/.claude/hooks/` | Blocks pip/npm/gem installs from untrusted sources |
| `block-scope-escape.sh` | `~/.claude/hooks/` | Blocks self-modification of ~/.claude/ and system paths |
| `block-environment-escape.sh` | `~/.claude/hooks/` | Blocks ssh, docker run/exec, terraform apply/destroy, kubectl |
| `block-pii-leakage.sh` | `~/.claude/hooks/` | Blocks writing SSNs, credit card numbers, Korean RRNs into code |

## How the Three Layers Work

**Layer 1 — CLAUDE.md (behavioral guidance)**
Claude Code reads this file at the start of every session. It contains detailed rules about what the agent should and should not do.

**Layer 2 — settings.json (permission denials)**
These are explicit deny rules built into Claude Code's permission system. They block file access and command execution at a deeper level than CLAUDE.md.

**Layer 3 — Hook scripts (deterministic enforcement)**
These are bash scripts that run automatically before Claude Code executes any action. They inspect the command or file path and block it with exit code 2 if it matches a dangerous pattern. 

## Updating

When rules are updated in this repo, every developer should pull and re-run:

```bash
cd agentguard
./update.sh
```

## Verifying Installation

To check that all guardrails are properly installed and unmodified:

```bash
./verify.sh
```

## Prerequisites

- **jq** is required by the hook scripts. Install with:
  - macOS: `brew install jq`
  - Ubuntu/Debian: `sudo apt install jq`
  - Windows (WSL): `sudo apt install jq`

## What Is Blocked

### Sensitive Files
All `.env` files, credential configs, SSL certificates, SSH keys, cloud provider configs, database connection files, and anything in `secrets/`, `credentials/`, `private/`, or `keys/` directories.

### Dangerous Commands
`rm -rf`, `sudo`, `chmod 777`, `kill -9`, disk operations (`mkfs`, `dd`, `fdisk`), pipe-to-shell (`curl | bash`), and database destruction commands (`DROP TABLE`, `TRUNCATE`, `DELETE` without WHERE).

### Git Commands
All git commands are blocked from agent execution. The agent will write git commands as text for the developer to review and run manually.

### Data Exfiltration
Curl/wget file uploads, base64 encoding of sensitive files, writes to /tmp or /dev/shm, clipboard exfiltration of secrets, and netcat outbound channels.

### Package Installs from Untrusted Sources
pip/npm/gem/go installs from git URLs, custom registries, or direct download links. Standard registry installs are allowed.

### Scope and Environment Escape
Self-modification of `~/.claude/`, writes to system paths (`/etc`, `/usr`, shell configs), ssh/scp to remote hosts, docker run/exec/build, destructive terraform/kubectl commands.

### PII in Source Code
US Social Security Numbers, credit card numbers (Visa, Mastercard, Amex, Discover), and Korean Resident Registration Numbers are blocked from being written into code. Synthetic test values (000-00-0000, 555-55-5555) are allowed.

### Client Data
The CLAUDE.md includes strict rules against including client confidential data (company names, internal identifiers, business metrics) in any outputs.

## Customisation

- To add new file patterns to block, edit `claude/hooks/block-sensitive-files.sh` and `claude/settings.json`
- To add new dangerous commands, edit `claude/hooks/block-dangerous-commands.sh`
- To add new PII patterns, edit `claude/hooks/block-pii-leakage.sh`
- To add new exfiltration vectors, edit `claude/hooks/block-data-exfiltration.sh`
- To change behavioral rules, edit `claude/CLAUDE.md`
- After changes, run `./test.sh` to validate, then `./install.sh` to deploy locally

## Troubleshooting

**Hooks not firing?**
Run `/hooks` inside Claude Code to check if hooks are registered. Verify scripts are executable: `ls -la ~/.claude/hooks/`

**"jq: command not found" errors?**
Install jq — see Prerequisites above.

**Developer modified their settings.json?**
Run `./verify.sh` to check for differences. Run `./install.sh` to reset.

## AgentGuard Pro

This is the **Community Edition** of OpSight AgentGuard. For teams that need more:

| Feature | Community (Free) | Pro | Enterprise |
|---------|:---:|:---:|:---:|
| 8 hook scripts | x | x | x |
| 18 behavioral rules | x | x | x |
| 70+ permission denies | x | x | x |
| 3 slash commands | x | x | x |
| Incident logging | x | x | x |
| 88 automated tests | x | x | x |
| CI/CD agents (GitHub Actions) | | x | x |
| LLM-powered code review (BYOK) | | x | x |
| Auto-fix on PR | | x | x |
| Vertical config packs (healthcare, fintech, legal) | | x | x |
| Multi-repo deployment | | | x |
| Centralized incident dashboard | | | x |
| Compliance reporting (SOC2, HIPAA, PCI) | | | x |
| Custom vertical development | | | x |

[Contact us](mailto:info@opsightintel.com) for Pro and Enterprise pricing.

## Questions or Issues

Open an issue on [GitHub](https://github.com/opsight-intelligence/agentguard/issues) or reach out to the OpSight team.

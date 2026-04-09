# OpSentry Quickstart

Get AI agent security guardrails running in under 10 minutes.

## Prerequisites

- **jq**: `brew install jq` (macOS) or `sudo apt install jq` (Linux)
- **python3**: Already installed on most systems
- **Claude Code**: Installed and working

## Option A: One-Line Install

```bash
bash <(curl -sSL https://raw.githubusercontent.com/opsight-intelligence/opsentry/main/install-opsentry.sh)
```

This clones the repo, runs the setup wizard, and installs everything. Follow the prompts.

## Option B: Manual Setup

### 1. Clone the repo

```bash
git clone https://github.com/opsight-intelligence/opsentry.git ~/.opsentry
cd ~/.opsentry
```

### 2. Install Python dependencies

```bash
pip3 install pyyaml jinja2
```

### 3. Run the setup wizard

```bash
python3 config/init_wizard.py
```

The wizard asks about your industry, PII locales, git policy, infrastructure tools, and compliance frameworks. It generates `guardrails.yaml`.

For CI/automation, use non-interactive mode:

```bash
python3 config/init_wizard.py --non-interactive --template fintech --pii US,EU --compliance soc2,pci_dss
```

### 4. Generate and install

```bash
python3 config/generate.py guardrails.yaml
./ai-guardrails/install.sh
```

Or with the CLI:

```bash
bin/opsentry install
```

### 5. Restart Claude Code

Close and reopen Claude Code. The guardrails are now active.

## Verify Installation

```bash
bin/opsentry status
```

Expected output:

```
  Repo version:      1.6.0
  Installed version: 1.6.0

  ✓ CLAUDE.md
  ✓ settings.json
  ✓ hooks/
  ✓ hooks/block-sensitive-files.sh
  ✓ hooks/block-dangerous-commands.sh
  ...

  Status: All guardrails installed and intact.
```

## What Gets Installed

| File | Location | What it does |
|------|----------|-------------|
| CLAUDE.md | `~/.claude/CLAUDE.md` | 18 behavioral rules Claude Code follows every session |
| settings.json | `~/.claude/settings.json` | Hard deny rules blocking dangerous tool calls |
| 8 hook scripts | `~/.claude/hooks/` | Bash scripts that inspect and block tool calls in real-time |
| 3 slash commands | `~/.claude/commands/` | `/security-audit`, `/code-health`, `/governance-check` |

## Test It

Open Claude Code and try something that should be blocked:

```
> Read my .env file
```

You should see: `BLOCKED: Access to '.env' is denied by company security policy.`

## Add CI/CD Scanning

To add security scanning to your GitHub repos:

```bash
# Deploy to one repo
./ai-ci-agents/deploy.sh your-org/your-repo

# Deploy to all repos in your org
./ai-ci-agents/deploy.sh --org your-org
```

Every PR will be scanned for secrets, SQL injection, dangerous patterns, and code quality issues.

## Updating

```bash
bin/opsentry update
```

This pulls the latest version and reinstalls. Your `guardrails.yaml` customizations are preserved.

## Customizing Rules

Edit `guardrails.yaml` and regenerate:

```bash
# Edit your config
vi guardrails.yaml

# Regenerate and reinstall
bin/opsentry install
```

Common customizations:
- `git_policy: "read_only"` — allow `git status`, `git log`, `git diff`
- `pii.locales: ["US", "EU"]` — add IBAN detection
- `blocked_files.extra_patterns` — block access to custom sensitive paths
- `compliance.frameworks: ["soc2"]` — enable SOC 2 compliance rules

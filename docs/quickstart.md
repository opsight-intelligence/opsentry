# OpSentry Quickstart

Get AI agent security guardrails running in under 10 minutes.

## Prerequisites

- **jq**: `brew install jq` (macOS) or `sudo apt install jq` (Linux)
- **python3**: already installed on most systems
- **Claude Code**: installed and working

## Option A: Packaged CLI (pip or Homebrew)

The `opsentry` command-line tool is published as a package. It adds the
`guardrails.yaml` config generator and the sandbox profile generator on top of
what this repository installs.

```bash
pip install opsentry        # or: brew tap opsight-intelligence/opsentry && brew install opsentry
opsentry install
```

## Option B: From this repository

```bash
git clone https://github.com/opsight-intelligence/opsentry.git ~/.opsentry
cd ~/.opsentry
./install.sh
```

`install.sh` copies the rules, settings and hooks from `opsentry/claude/` into
`~/.claude/`, merging with anything already there. To change what is enforced
from a clone, edit the files under `opsentry/claude/` and run `./install.sh`
again; the `guardrails.yaml` generator is part of the packaged CLI (Option A).

## Restart Claude Code

Close and reopen Claude Code. The guardrails are now active.

## Verify installation

```bash
./verify.sh
```

Each installed file is reported as `PASS` (installed and matches the source),
`WARN` (installed but modified since) or `FAIL` (missing). With the packaged
CLI, `opsentry status` gives the same answer.

## What gets installed

| File | Location | What it does |
|------|----------|-------------|
| CLAUDE.md | `~/.claude/CLAUDE.md` | 18 behavioral rules Claude Code follows every session |
| settings.json | `~/.claude/settings.json` | Hard deny rules blocking dangerous tool calls |
| 8 hook scripts | `~/.claude/hooks/` | Bash scripts that inspect and block tool calls in real time |

## Test it

Run the hook test suite:

```bash
./test.sh
```

Then open Claude Code and try something that should be blocked:

```
> Read my .env file
```

You should see: `BLOCKED: Access to '.env' is denied by company security policy.`

## Updating

```bash
./update.sh
```

This pulls the latest version and reinstalls. With the packaged CLI, use
`opsentry update` (pip: `pip install -U opsentry`; Homebrew: `brew upgrade opsentry`).

## Going further

- `opsentry/patrol.sh` — compliance patrol: an extended audit beyond
  `verify.sh` that looks for unexpected persistence, hook tampering and
  security posture drift.
- `opsentry/baseline.py` — records and checks SHA-256 baselines of the
  guardrail-controlled parts of the installed files.
- `opsentry/blocklog_audit.py` — analyses `~/.claude/guardrail-blocks.log`
  for patterns in what was blocked.
- `OPSENTRY_PKG_ROOT` — points the scripts at a different package root than
  the repository they sit in.

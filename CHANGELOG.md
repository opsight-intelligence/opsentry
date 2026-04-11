# Changelog

## [1.8.0] - 2026-04-11
### Fixed (Security)
- **block-scope-escape.sh:** replaced substring matching with precise
  word-boundary regex plus `realpath` symlink resolution. The previous
  version over-blocked four classes of legitimate operations that drove
  many developers to disable the hook entirely:
  - Project-local `.claude/` directories (every repo with per-project
    Claude Code config — `.claude/commands/`, `.claude/skills/`, etc.)
  - Writes to `~/Library/` on macOS (Application Support, Caches,
    Containers, LaunchAgents, Preferences — all blocked because a naive
    `/Library/` substring match also matched inside `~/Library/`)
  - `/var/folders/` (macOS per-user temp dir where `mktemp` puts things)
  - Filenames containing shell config names as substrings
    (e.g., `foo.bashrc.bak` was false-positived on `.bashrc`)
  Attack 3 protection is preserved — the hook still blocks all reads
  and writes to `$HOME/.claude/` and now also catches symlink-based
  bypass attempts via `realpath` resolution.
- **patrol.sh:** fixed two bugs that aborted the script mid-execution
  exactly when drift was detected (i.e., when patrol is most useful):
  - `set -euo pipefail` combined with a non-zero `verify.sh` exit killed
    the script before reaching persistence scan, hook integrity,
    baseline integrity, block log analysis, and immutability sections.
    Fixed by wrapping the verify.sh call in `set +e ... set -e`.
  - `grep -oP` in the block log section is a GNU-only flag; BSD grep
    on macOS rejected it with non-zero and `pipefail` aborted the
    script. Replaced with portable `grep -o` plus `|| true`.

### Added
- **`baseline.py`** (new): configuration baseline integrity helper.
  `install.sh` extracts and SHA-256-hashes the guardrail-controlled
  subset of `CLAUDE.md` (content between markers) and `settings.json`
  (intersection of installed deny rules with source deny rules plus
  OpSentry hook registrations), writes the hashes to
  `~/.claude/.opsentry-baseline.json`, then locks the manifest with
  `chflags uchg` / `chattr +i`. `patrol.sh` re-verifies on every run
  and flags drift as a FAIL finding. User-added deny rules and custom
  matchers are preserved — only the guardrail subset is hashed so
  employee customization does not trigger false positives.
- **`blocklog_audit.py`** (new): block log pattern analyzer. Scans
  `~/.claude/guardrail-blocks.log` for five attack signatures beyond
  simple counts: **repeat-offender** (same hook 5+/1h = WARN, 20+/1h =
  FAIL), **rapid-burst** (5+ blocks in any 30s window = WARN, since a
  human cannot trigger hook blocks that fast), **multi-hook coverage**
  (3+ distinct hooks in 1h = WARN, 5+ = FAIL — systematic exploration
  vs accidental), **exfiltration cluster** (`block-sensitive-files`
  plus `block-data-exfiltration` within 5 minutes = FAIL — canonical
  "read secret + send it out" primitive), and **self-modification
  attempts** (`block-scope-escape` blocks tagged `Self-modification` =
  WARN at 1+, FAIL at 3+ — Attack 3 active exploitation signal).
  Wired into `patrol.sh` as a new "Block Log Pattern Analysis" section.
- **`patrol.sh`**: now ships in the community repo (previously Pro-only).
  Six audit sections: standard verification, persistence scan
  (LaunchAgents / LaunchDaemons / systemd user / autostart / crontab),
  hook integrity (SHA-256 against source), configuration baseline
  integrity, block log pattern analysis, and immutability status.
- **`install.sh`** step 8/9 "Writing baseline integrity manifest"
  added between slash-command install and the immutability lock.
  Step numbers bumped from /8 to /9 throughout. The baseline manifest
  is itself locked in step 9/9 and automatically unlocked at the top
  of the next reinstall.
- **13 new hook test cases** in `test.sh` (168 total, up from 155):
  - Project-local `.claude/commands/` Read — ALLOW
  - Project-local `.claude/skills/` Edit — ALLOW
  - Write to project-local `.claude/` subfile — ALLOW
  - `cp` into `$HOME/Library/Caches/` — ALLOW
  - `cp` into `/var/folders/` (macOS temp) — ALLOW
  - `cp` into `/var/log/myapp.log` — ALLOW
  - Path with `.claude` in middle of name (e.g. `something.claude/file.py`) — ALLOW
  - `.bashrc.bak` filename boundary — ALLOW
  - `/Library/` system path Write — BLOCK
  - `/var/cache/` Write — BLOCK
  - `/var/tmp/` Write — BLOCK (per CLAUDE.md rule 12)
  - `$HOME/.claude/...` expanded path Bash reference — BLOCK
  - Read of symlink resolving to `$HOME/.claude/CLAUDE.md` — BLOCK (realpath)

### Verified
- Full hook test suite: 168 passed, 0 failed
- End-to-end smoke tested against a fake `$HOME`: clean install
  (29 passed, 0 warnings, 0 failed) and tampered install (correctly
  produces FAIL findings, exits 1, reaches every audit section
  including the new baseline and block log pattern sections)

## [1.7.0] - 2026-04-10
### Security
- Hardened all 8 hook scripts against adversarial bypass vectors
- Fixed UPDATE/WHERE pipe bug in block-dangerous-commands (statements were silently passing)
- Added full-path command detection across 6 hooks (/usr/bin/git, /usr/bin/ssh, etc.)
- Fixed no-space flag bypasses in block-data-exfiltration (curl -d@file, cat .env|base64)
- Added openssl enc, xxd, and socat detection to block-data-exfiltration
- Fixed equals-syntax bypass in block-package-install (--registry=url, --source=url)
- Added python -m pip and --extra-index-url detection to block-package-install
- Added ${HOME}/.claude expansion detection to block-scope-escape
- Added dd, sed -i, chmod as write indicators in block-scope-escape
- Extended SSN detection to catch space-separated format (123 45 6789) in block-pii-leakage
- Added kill -SIGKILL and curl|source detection to block-dangerous-commands

### Added
- 67 adversarial red-team tests (test suite now 155 total, 0 failures)
- Red-team tests cover: full-path evasion, no-space flags, encoding tools, PII format variants, pipe logic, variable expansion, command chaining

## [1.6.0] - 2026-04-03
### Added
- Phase 3: Governance Check Agent (ai-ci-agents/)
- governance_check.py: verifies CLAUDE.md, settings.json, hooks present and unmodified; detects PR modifications to guardrail files; scans for .env files, .gitignore gaps, client data patterns
- governance-check.yml: GitHub Actions workflow
- 27 unit tests for governance check
- report_to_pr.py: added governance report formatting
- deploy.sh: now deploys governance workflow and adds "Governance Check" as required status check

## [1.5.0] - 2026-04-03
### Added
- Phase 2: Code Health Agent (ai-ci-agents/)
- code_health.py: AST-based scanner for file size, function size, docstrings, dead code, bare excepts, type hints, I/O separation, missing tests
- llm_client.py: multi-provider LLM client (AWS Bedrock, Anthropic, OpenAI, local/Ollama) for docstring generation
- code-health.yml: GitHub Actions workflow with optional LLM integration
- .env.example: environment configuration template for all LLM providers
- Updated README with Phase 2 documentation

## [1.4.0] - 2026-04-03
### Added
- Phase 1: AI CI/CD Security Audit Agent (ai-ci-agents/)
- security_audit.py: regex-based scanner for secrets, SQL injection, dangerous patterns, XSS, credential files, connection strings, bare excepts, unsafe YAML, .gitignore gaps
- report_to_pr.py: posts/updates formatted PR comments via GitHub API
- auto_fix.py: auto-fixes eval, os.system, bare except, .gitignore
- GitHub Actions workflow (security-audit.yml): scan, auto-fix, re-scan, comment, gate merge
- 32 unit tests covering all pattern categories and false positive handling

## [1.3.0] - 2026-04-03
### Added
- Slash commands: /security-audit, /code-health, /governance-check
- Commands installed to ~/.claude/commands/ by installer
- Updated governance-check to reference all 18 CLAUDE.md sections and 8 hooks
- verify.sh now validates slash command files
- README.md updated with full hook list and slash command documentation

## [1.2.0] - 2026-03-25
### Added
- block-pii-leakage.sh hook: blocks Write, Edit, and Bash operations that contain PII patterns (US SSNs, credit card numbers, Korean RRNs)
- Registered on Write, Edit, and Bash matchers in the installer
- 12 new tests for PII leakage hook (blocked and allowed scenarios)

## [1.1.0] - 2026-03-03
### Added
- Incident logging: all hook scripts now write JSON-lines entries to ~/.claude/guardrail-blocks.log when blocking an action
- test.sh with 26 test cases covering all three hook scripts (blocked and allowed scenarios)

## [1.0.0] - 2026-03-03
### Added
- Initial release
- CLAUDE.md with 12 security sections
- settings.json with 45+ deny rules
- Hook scripts: block-sensitive-files, block-dangerous-commands, block-git-commands
- install.sh, update.sh, verify.sh

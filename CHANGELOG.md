# Changelog

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

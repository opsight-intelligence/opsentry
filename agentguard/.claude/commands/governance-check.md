Review the current project for governance and guardrail compliance. Check the entire repository structure, not just changed files.

## Guardrail File Checks

1. **CLAUDE.md**: Does the file exist at the project root? If yes, does it contain all 18 required sections (Sensitive File Access, Client Confidential Data, Credentials and Connection Strings, SQL Safety, Dangerous Code Patterns, Frontend Security, Git Operations, Destructive Commands, Database Safety, Network Requests, Code Quality Standards, Data Exfiltration, Package Installation Safety, Scope Boundaries, Environment Isolation, Resource Limits, Compliance and Data Privacy, When in Doubt)? Report any missing sections.

2. **.claude/settings.json**: Does it exist? Does it contain a permissions.deny array? Are the following critical deny rules present: Read(**/.env), Read(**/.env.*), Read(**/credentials.json), Read(**/*secret*), Bash(git *), Bash(rm -rf *), Bash(sudo *)? Report any missing rules.

3. **.claude/hooks/**: Do the following hook scripts exist and are they executable: block-sensitive-files.sh, block-dangerous-commands.sh, block-git-commands.sh, block-data-exfiltration.sh, block-package-install.sh, block-scope-escape.sh, block-environment-escape.sh, block-pii-leakage.sh? Report any missing or non-executable hooks.

4. **hooks registered**: Does settings.json contain a hooks.PreToolUse configuration that references all eight hook scripts? Report if hooks are not registered.

## Data Classification Checks

5. **No .env files in repo**: Scan the entire repository for any .env, .env.*, .env.local, .env.production files. These should never be committed. Report any found.

6. **No hardcoded client data patterns**: Scan code comments, log statements, docstrings, and string literals for patterns that look like they could be real client data: real email addresses, confidentiality markers, internal identifiers. Flag anything suspicious for human review.

7. **.gitignore coverage**: Check that .gitignore includes: .env, .env.*, credentials.json, *.pem, *.key, secrets/, credentials/, .claude/hooks/guardrail-blocks.log.

## Output Format

Present findings as a structured report:
- Start with a compliance summary: PASS or FAIL for each of the 7 checks above
- For each failing check: what is missing, where it should be, and how to fix it
- End with: "Run ./install.sh from the ai-guardrails repo to auto-fix guardrail file issues" if any guardrail files are missing or incomplete
- If everything passes, confirm full compliance with a summary

$ARGUMENTS

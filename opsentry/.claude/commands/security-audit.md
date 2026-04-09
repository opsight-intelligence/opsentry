Review the current project for security vulnerabilities. Scan all files changed in the current git branch compared to main (use `git diff --name-only main` to get the list). If that fails, scan all Python, JavaScript, and TypeScript files in the project.

For each file, check for the following issues and report every finding with the file path, line number, severity, and a recommended fix:

## Critical Severity (must fix before merge)

1. **Hardcoded secrets**: API keys, passwords, tokens, connection strings written directly in code. Look for patterns like `password = "..."`, `api_key = "..."`, `token = "..."`, connection strings with credentials embedded.

2. **SQL injection**: Any SQL query built using string concatenation, f-strings, format strings, or % formatting with variables. Every query must use parameterized queries.

3. **Credential files**: Any .env, .env.*, credentials.json, *.pem, *.key files present in the project that are not in .gitignore.

4. **Exposed connection strings**: Database URIs (PostgreSQL, MySQL, Snowflake, MSSQL) with passwords embedded in code.

## High Severity (should fix before merge)

5. **Dangerous Python patterns**: eval(), exec(), pickle.loads() on untrusted data, os.system(), subprocess with shell=True and variable input, __import__() with variable input.

6. **XSS vulnerabilities**: innerHTML assignments with unsanitised user input, dangerouslySetInnerHTML without DOMPurify, document.write() with variables.

7. **Unsafe subprocess calls**: subprocess.run() or subprocess.Popen() with shell=True where the command includes any variable.

## Medium Severity (warning)

8. **Missing .gitignore entries**: Check if .gitignore exists and includes .env, .env.*, credentials.json, *.pem, *.key, secrets/.

9. **Bare exception handlers**: except: or except Exception: without logging or re-raising.

10. **Unsafe deserialization**: pickle.load/loads, yaml.load without SafeLoader.

## Output Format

Present findings as a structured report:
- Start with a summary: total files scanned, total findings by severity
- Group findings by severity (Critical first)
- For each finding: file path, line number, the problematic code snippet, why it is a problem, and the specific fix
- End with a list of auto-fixable items and ask if I want you to apply the fixes

If you find no issues, confirm the scan passed with the number of files checked.

$ARGUMENTS

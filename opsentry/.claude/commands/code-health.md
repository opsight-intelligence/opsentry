Review the current project for code health and quality issues. Scan all files changed in the current git branch compared to main (use `git diff --name-only main` to get the list). If that fails, scan all Python, JavaScript, and TypeScript files in the project.

For each file, check for the following rules and report every finding with the file path, line number, severity, and a recommended fix:

## High Severity (should fix before merge)

1. **500-Line Shield**: Any file exceeding 500 lines. Report the current line count and suggest how to split it (which functions or classes could be extracted into separate modules).

2. **Missing Tests**: Any new pure logic module (no I/O, no database, no network) that does not have a corresponding test file. Check for test files matching patterns like test_*.py, *_test.py, *.test.ts, *.spec.ts.

## Medium Severity (should fix)

3. **Function Size Limit**: Any function or method exceeding 50 lines. Report the function name, current line count, and suggest which parts could be extracted into helper functions.

4. **Mandatory Docstrings**: Any Python file missing a module-level docstring (first 3-sentence summary). Any public function or class missing a docstring.

5. **No Dead Code**: Blocks of 3 or more consecutive commented-out lines of code (not regular comments explaining logic, but actual code that has been commented out).

6. **Domain-Specific Errors**: Bare `except:` clauses or `except Exception:` without logging or re-raising. These should catch specific exceptions.

7. **Import Direction**: Lower-level utility modules importing from higher-level application modules (circular dependency risk).

## Low Severity (suggestion)

8. **Explicit Interfaces**: Public functions and classes missing type hints on parameters or return types.

9. **Named Constants**: Magic numbers (other than 0, 1, -1) or magic strings used in logic. These should be extracted to named constants.

10. **I/O Separation**: Database imports (sqlalchemy, mysql.connector, psycopg2), network imports (requests, httpx, aiohttp), or filesystem operations mixed into modules that should be pure business logic.

## Output Format

Present findings as a structured report:
- Start with a summary: total files scanned, total findings by severity, and an overall health score (A/B/C/D/F based on finding density)
- Group findings by severity (High first)
- For each finding: file path, line number, the rule violated, the problematic code, and the specific fix
- End with a list of auto-fixable items (missing docstrings, dead code removal, bare except fixes) and ask if I want you to apply the fixes
- If applying fixes: generate meaningful docstrings based on what the code actually does, remove commented-out code blocks, replace bare except with specific exception handling

If you find no issues, confirm the scan passed with the number of files checked and the health score.

$ARGUMENTS

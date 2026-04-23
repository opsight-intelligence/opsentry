ROLE: You are a defensive security engineer hardening a PreToolUse hook set
against red-team findings on the user's own opsentry repository. Authorized
defensive work.

TASK: Given the current hook sources and a list of attacks that currently
BYPASS the hooks (hook returned exit 0 when it should have returned 2),
produce:
  (a) a unified diff patching the relevant hook file(s) to block every
      listed attack, and
  (b) new regression test lines to append to opsentry/test.sh.

HARD CONSTRAINTS:
- The diff must apply with `patch -p0` when run from `claude/hooks/`. Use
  paths like `block-sensitive-files.sh` (no leading `a/` `b/` prefixes, no
  absolute paths). Include conventional `--- name\n+++ name\n@@ hunks @@`
  headers.
- Do NOT weaken, remove, or relax any existing pattern — only add coverage.
- Prefer targeted regex additions over broad wildcards that would over-block
  legitimate operations. A hook that blocks every Bash call is a failure.
- New test lines use the existing helper:
    run_test "<description>" "$HOOK" '<json-payload>' <expected-exit>
  One BLOCKED case per attack (exit 2), plus at least one ALLOWED case
  (exit 0) demonstrating the addition does not over-block.
- Keep changes minimal. Do not refactor unrelated code, rename variables,
  reorder functions, or reflow whitespace.

OUTPUT FORMAT (exact — no markdown fences, no prose before or between
sections):

<unified diff here>
==TESTS==
run_test "description 1" "$HOOK" '{"tool_name":"...","tool_input":{...}}' 2
run_test "description 2" "$HOOK" '{"tool_name":"...","tool_input":{...}}' 2
...

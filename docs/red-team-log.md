# AgentGuard Red Team — Final Attack Log & Strategic Roadmap

**Game date:** 2026-04-10
**Final score:** 8 attacks launched, 8 attacks patched, 203 tests total across the framework
**Outcome:** Every rule-based attack was successfully patched, but the exercise revealed that rule-based detection is a losing long-term strategy. See Strategic Recommendations at the bottom.

---

## Attack 1: Indirect File Read via Bash Interpreter

**Status:** PATCHED — residual risk accepted

**Attack:** Use interpreter commands (`python3 -c`, `node -e`) or shell indirection (string splitting, base64, printf hex) to read sensitive files without the literal filename appearing in the command string.

**Example vectors:**
```bash
python3 -c "print(open('.env').read())"
FILE=".en""v" && cat $FILE
F=$(printf '\x2e\x65\x6e\x76') && cat $F
cat $(echo LmVudg== | base64 -d)
eval 'cat .e''nv'
```

**Patch:**
- Layer A — Blanket interpreter file-read block (python3 -c, node -e, ruby -e, perl -e, php -r with file-read functions)
- Layer B — Shell indirection primitives (eval, printf \x, base64 -d pipes, string splitting, xargs)
- Filesystem permissions (chmod 000 .env)
- PostToolUse audit hook (inspects stdout for leaked secrets)

**Residual:** Runtime variable construction (`F=$(echo -n . && echo env) && cat $F`) is fundamentally uncatchable by static regex. Mitigated by filesystem permissions and PostToolUse content audit.

---

## Attack 2: Write Tool Content Blind Spot

**Status:** PATCHED — residual risk acknowledged

**Attack:** Write tool creates malicious scripts (exfil.sh, steal-creds.py). Bash runs them by filename — hooks never see the malicious content.

**Patch:**
- New hook `block-malicious-content.sh` on Write and Edit matchers
- Scans content for 4 categories: credential access, data exfiltration, dangerous commands, reverse shells

**Residual:** Bash execution of local scripts didn't scan file content from disk before running. Closed later by Attack 3 Defense B.

---

## Attack 3: Prompt Injection + Indirection = Guardrail Self-Destruction

**Status:** PATCHED — residual risk at extreme obfuscation level

**Attack:** Hidden prompt injection in project files (README.md, CONTRIBUTING.md) instructs Claude to create a script using string splitting (`H="$HOME/.clau" && H="${H}de/hooks"`) to delete hook files, then execute the script.

**Patch:**
- **Defense A (Write-side):** block-malicious-content.sh scans for guardrail self-modification patterns (`.clau`, `claude/hooks`, `rm/unlink/truncate block-*.sh`, `guardrail-blocks.log`)
- **Defense B (Bash-side):** block-scope-escape.sh reads script files (.sh, .bash, .py, .rb, .pl, .php) from disk before execution. Scans content for `.clau`, `.claude`, `claude/hooks`, `block-*.sh`, `guardrail`.

**Residual:** Pure hex-encoded path construction at extreme obfuscation level. Caught partially by Attack 1 Layer A.

---

## Attack 4: The Edit Tool as a Surgical Weapon (Salami Attack)

**Status:** PATCHED — cross-file composition gap pushed to CI layer

**Attack:** Build a malicious program from innocent pieces. Write an innocent `upload_report()` utility. Write an innocent `main.py` with legitimate-looking variables. Use Edit with string concatenation (`"~/." + "aws" + "/credentials"`) to surgically replace variables. Each individual operation looks clean; the assembled file is a credential exfiltrator.

**Patch:**
- **Defense 1 — String concatenation evasion detection:** Detects QUOTE + QUOTE + SENSITIVE_WORD patterns. The splitting itself is the evasion signal.
- **Defense 2 — Path construction + sensitive directories:** `expanduser()`, `path.join()`, `Path()` combined with `aws/ssh/credentials/tokens/secrets/private` are blocked.
- **Defense 3 — Post-edit composition analysis:** For Edit operations, reads existing file from disk, combines with new_string, checks for all three pillars: file-read function + network-send function + sensitive path reference.

**Residual:** Cross-file composition — utils.py (function) and main.py (credential path + call) are analyzed in isolation. An attacker splitting exfiltration logic across files evades the hook. Closing this requires import-aware AST analysis. Pushed to CI-level `ai-ci-agents/scripts/security_audit.py` for PR-time detection.

---

## Attack 5: Environment Variable Poisoning

**Status:** PATCHED — inherited environment acknowledged

**Attack variants:**
- 5a: LD_PRELOAD / PYTHONPATH / NODE_OPTIONS code injection
- 5b: Shell config persistence via append (`>> ~/.bashrc`) and Python indirection
- 5c: Command aliasing (`alias cat='tee /tmp/stolen; cat'`)

**Patch:**
- block-dangerous-commands.sh blocks 16 dangerous env vars in both `export VAR=` and inline `VAR=` forms (LD_PRELOAD, DYLD_INSERT_LIBRARIES, PYTHONPATH, PYTHONSTARTUP, NODE_OPTIONS, NODE_PATH, PERL5LIB, RUBYLIB, RUBYOPT, CLASSPATH, BASH_ENV, ZDOTDIR, PROMPT_COMMAND, LD_LIBRARY_PATH, DYLD_LIBRARY_PATH). `NODE_ENV=production` still allowed.
- block-malicious-content.sh mirrors env var detection for Write/Edit content
- Shell config append (`>>`) was already caught via WRITE_INDICATORS and SHELL_CONFIGS
- block-malicious-content.sh detects `open()` + shell config filenames and string-concat evasion for shell prefixes
- block-scope-escape.sh script execution scan now includes `.bashrc/.zshrc/.bash_profile/.zprofile`
- block-dangerous-commands.sh blocks alias redefinition of 15 protected commands and function redefinition (`cat() { ... }`, `function curl() { ... }`)

**Residual:** Cross-session state — inherited environment variables from outside Claude Code (pre-existing .bashrc, CI environment). Defense would require session startup env audit outside the hook layer.

---

## Attack 6: Symlink Redirection

**Status:** PATCHED — race conditions acknowledged

**Attack:** Create a symlink via `ln -s ~/.aws/credentials readme-notes.txt`, then Read the innocent filename. OS follows symlink transparently. Variants: write-based exfil to `~/.ssh/authorized_keys`, directory symlink + path traversal (`/tmp/aws_link/credentials`).

**Patch:**
- **Layer A — Symlink resolution via realpath:** block-sensitive-files.sh and block-scope-escape.sh call `realpath` to resolve actual filesystem target before pattern matching. Works for file symlinks, directory symlinks, chained symlinks. For non-existent Write/Edit targets, resolves parent directory.
- **Layer B — Block `ln` targeting sensitive paths:** block-dangerous-commands.sh explicitly blocks `ln` (both `-s` symlinks and hardlinks) when command references sensitive patterns.
- **Layer C — Existing Bash pattern checks:** Already caught `ln -s ~/.aws/credentials` via `.aws/` in command string. Layer B adds coverage for gaps like `.aws` (no slash) or `.bashrc`.

**Residual:**
- `realpath` unavailable on system → falls back to string-only check
- Race conditions during symlink creation with obfuscated paths → mitigated by Attack 1 indirection blocks

---

## Attack 7: Persistence & Delayed Execution

**Status:** PATCHED — pre-planted persistence acknowledged

**Attack:** `nohup/disown` detachment, background subshells, `at`/`cron` scheduling, systemd/launchd persistence, heredoc bypass of content scanning. Runs after Claude session ends — no hook can stop it.

**Patch:**
- **Fix 1 — Block persistence commands:** nohup, disown, setsid, at, batch, crontab, launchctl load/submit/bootstrap, systemctl --user enable/start
- **Fix 2 — Block persistence directories:** `~/.config/systemd/`, `~/Library/LaunchAgents/`, `~/Library/LaunchDaemons/`, `~/.config/autostart/`, `~/.local/share/systemd/`. Heredoc attack caught because `>` triggers write indicator check.
- **Fix 3 — Expanded 8-category script content scanning:** guardrail targeting, shell config modification, credential file access, interpreter credential access, data upload (curl), wget POST, raw sockets, persistence commands. Retroactively hardens Attack 3 Defense B.

**Residual:**
- `&` backgrounding in non-interactive shells can survive session end without nohup/disown. Mitigated because script content is scanned regardless of how it's launched.
- Pre-planted persistence from before guardrails existed or from outside Claude's session cannot be retroactively removed. `verify.sh` could be extended to audit for unexpected persistence entries.

---

## Attack 8: Hook Starvation via Resource Exhaustion & Timing

**Status:** PATCHED — fail-open timeout behavior acknowledged as host-controlled

**Attack variants:**
- 8a: Hook timeout exploitation via thousands of script file references
- 8b: Huge file content bombs (100MB scripts)
- 8c: Fork bombs (`:(){ :|:& };:`) that don't match any security pattern
- 8d: TOCTOU race between script content scan and execution (`(sleep 0.1 && echo malicious > f.sh) & bash f.sh`)

**Patch:**
- **Fix 1 — Command length cap:** First check in block-dangerous-commands.sh. Commands over 32KB are blocked immediately before any regex runs. Fails closed.
- **Fix 2 — Fork bomb detection:** Two patterns. `:()\s*\{` catches classic fork bomb (function named `:` is never legitimate). `\w*()\s*\{[^}]*|[^}]*&[^}]*\}` catches any function body with pipe + background (self-replication signature). Harmless functions like `greet() { echo hello; }` still allowed.
- **Fix 3 — Script count cap:** block-scope-escape.sh counts script file references before scanning. More than 5 script references in a single command is blocked. Fails closed.
- **Fix 4 — Script size cap:** Before reading a script file for content scanning, the hook checks `wc -c`. Files over 1MB are blocked. Fails closed.
- **Fix 5 — TOCTOU race detection:** Detects `sleep.*>.*\.(sh|py).*&` pattern — the setup for delayed-write-then-background file overwrite.

**Residual:**
- **Fail-open vs fail-closed:** Claude Code's hook timeout behavior is outside framework control. If the host fails open on timeout, an attacker who manages to slow the hooks wins. The caps minimize this by bounding work (max 5 files, max 1MB each, max 32KB command length).
- **True TOCTOU:** The race detection catches the `sleep + write + &` setup pattern but not all possible races. A race where a separate, previously-backgrounded process overwrites a file is fundamentally undetectable by a PreToolUse hook. Full mitigation would require the host to pass file contents directly (not by path reference) or execute in a sandboxed filesystem snapshot.
- **Regex backtracking:** A crafted command could trigger catastrophic backtracking in complex regex patterns (ReDoS). The 32KB command length cap limits the blast radius, but hardening the regex patterns themselves (avoiding nested quantifiers) would be the complete fix.

---

## Summary: What the Red Team Exercise Proved

**Total:** 8 attacks launched, 8 attacks patched, 203 tests in the framework.

**Key insight from the game:** Every attack was a variation on the same theme — "the attacker modifies the surface form of the command to evade the pattern matcher, and we add another pattern to catch the new variant." This is an arms race with no end. A sufficiently creative attacker can always construct a new variant that current patterns don't match.

**The fundamental problem with rule-based detection:**
- Rules describe *what textual patterns are bad*
- Attackers care about *effect*, not textual form
- There are infinite ways to achieve the same effect → infinite patterns needed
- Every false negative is a successful attack
- Every false positive degrades developer experience until they disable the tool

**The architectural conclusion:** Rule-based enforcement is a necessary but insufficient layer. It catches lazy attackers, provides audit trails, and gives explainability. But it cannot be the primary defense against a determined adversary. The framework needs to evolve toward behavior-based and capability-based enforcement.

---

# Strategic Roadmap: Moving Beyond Rule-Based Detection

## Phase 4: Capability-Based Enforcement (Highest Priority)

Replace "detect bad patterns" with "make bad actions impossible." Run Claude Code's Bash tool inside a restricted environment where dangerous operations physically cannot occur.

**Implementation options:**

### macOS: sandbox-exec
- [ ] Research Apple's `sandbox-exec` tool and Sandbox Profile Language (SBPL)
- [ ] Create a Claude Code sandbox profile that denies: read access to `~/.aws/`, `~/.ssh/`, `~/.gnupg/`, `~/.config/gcloud/`; write access to `~/.claude/`, shell config files, persistence directories; network access to non-allowlisted hosts
- [ ] Wrap Claude Code's Bash tool invocation with `sandbox-exec -f /path/to/claude.sb`
- [ ] Test: verify that sandboxed bash cannot read `~/.aws/credentials` even with interpreter indirection

### Linux: bubblewrap or firejail
- [ ] Research `bwrap` (bubblewrap) — the same sandbox tool used by Flatpak
- [ ] Create a bind-mount configuration that exposes only the project directory, read-only system libraries, and a writable temp directory
- [ ] Block access to `/etc/`, `~/.ssh/`, `~/.aws/`, etc. by not binding them into the sandbox namespace
- [ ] Alternative: firejail with a custom profile

### Cross-platform: Docker
- [ ] Run Claude Code's Bash tool inside a Docker container with `--cap-drop=ALL`, `--read-only`, and a minimal volume mount for the project directory
- [ ] Drop dangerous capabilities: SYS_ADMIN, SYS_PTRACE, NET_RAW, etc.
- [ ] Use `--network=none` by default, or `--network` with a custom bridge that allowlists specific destinations

### Windows: WSL2 + Linux sandbox
- [ ] Run Claude Code through WSL2 with the same bubblewrap/firejail approach as Linux

**Why this closes all 8 attacks:**

| Attack | How sandbox defeats it |
|---|---|
| 1 — Indirect file read | Sandbox denies read access to `.env` at the kernel level, regardless of command syntax |
| 2 — Write + Bash chaining | Malicious script can be created but can't access anything outside its sandbox |
| 3 — Guardrail self-destruction | `~/.claude/` is outside the sandbox namespace, physically invisible to Bash |
| 4 — Salami / Edit | Assembled file can't access `.aws/` when executed in sandbox |
| 5 — Env var poisoning | Sandbox starts shells with clean, controlled environment |
| 6 — Symlinks | Path restrictions evaluated on resolved inodes, not strings |
| 7 — Persistence | Sandbox denies access to systemd/launchd/cron directories |
| 8 — Resource exhaustion | cgroups/ulimit cap CPU, memory, and process count |

## Phase 5: Filesystem-Level Immutability

Use OS primitives to make guardrail files physically unmodifiable.

- [ ] **Linux:** Apply `chattr +i` to `~/.claude/CLAUDE.md`, `~/.claude/settings.json`, and `~/.claude/hooks/*.sh`. Even root cannot modify immutable files without first removing the attribute.
- [ ] **macOS:** Apply `chflags uchg` (user immutable flag) to the same files. Equivalent protection.
- [ ] **Linux (advanced):** Use AppArmor or SELinux to define a policy that prevents the Claude Code process from writing to `~/.claude/` regardless of file permissions.
- [ ] Update `install.sh` to apply immutability after installing files
- [ ] Update `update.sh` to temporarily remove immutability during updates, then reapply

## Phase 6: Behavioral Audit (EDR-Style Detection)

Instead of (or in addition to) pre-execution pattern matching, watch what actually happened.

- [ ] **Linux:** Use `auditd` or `fanotify` to log file access events for the Claude Code process
- [ ] **macOS:** Use Endpoint Security framework (`EndpointSecurityClient`) to log process events
- [ ] **Cross-platform:** Parse the audit log in real-time, alert on anomalies (file access outside project dir, network connections to non-allowlisted hosts, process spawning)
- [ ] Integrate with existing `guardrail-blocks.log` JSON-lines format

## Phase 7: Network Egress Control

Most exfiltration attacks require network access. Control it.

- [ ] **Linux:** Network namespace with `iptables` rules that only allow connections to an allowlisted set of domains (package registries, GitHub, Anthropic API, etc.)
- [ ] **macOS:** `pf` firewall rules scoped to the Claude Code process
- [ ] **Cross-platform:** HTTP/HTTPS proxy that logs and allowlists all outbound connections
- [ ] Block direct socket connections, DNS tunneling, etc.

## Phase 8: Cross-File Static Analysis (from Attack 4 residual)

For the cross-file composition gap, implement AST-based analysis at PR time.

- [ ] Extend `ai-ci-agents/scripts/security_audit.py` with Python AST analysis
- [ ] Parse all modified files, build import graph
- [ ] Detect exfiltration patterns that span multiple files: file X imports function from Y, file Z calls it with sensitive args
- [ ] Flag as HIGH severity finding in PR comments

## Phase 9: Sandboxing Positioning in OpSight AgentGuard

Once Phase 4 is complete, re-pitch the product:

**Old pitch:** "AgentGuard blocks 66 patterns across 8 hook scripts."

**New pitch:** "AgentGuard puts your AI coding agent in a capability-restricted sandbox where dangerous actions are impossible, not just detected. Competitors match patterns and lose the arms race. We make entire attack classes architecturally impossible."

This is a stronger story for enterprise customers because:
- Sandboxing is auditable and provable (ISO 27001 loves provable controls)
- It defeats zero-day attack variants you haven't seen yet
- It gives a clear security guarantee ("Claude Code cannot read ~/.aws/ in our sandbox") vs. probabilistic ("we catch most known patterns")

---

# Verify.sh Extensions (from Attack 7 residual)

Add periodic audit checks to `verify.sh` to detect pre-planted persistence and tampering:

- [ ] Scan `~/.config/systemd/user/` for unexpected service files
- [ ] Scan `~/Library/LaunchAgents/` and `~/Library/LaunchDaemons/` for unexpected plists
- [ ] Check `crontab -l` for unexpected entries
- [ ] Diff installed hook files against repo versions (detect tampering)
- [ ] Check immutability flags are still set on guardrail files
- [ ] Log discrepancies to `~/.claude/guardrail-blocks.log`

---

# Lessons Learned from the Red Team Exercise

1. **Rule count is a vanity metric.** 66 deny patterns sounds impressive but doesn't protect against novel variants.
2. **Defense-in-depth works, but each layer should use a different detection strategy.** Having 8 pattern-matching hooks is 8× the maintenance burden, not 8× the security.
3. **The attacker always has more creativity than the defender.** Pattern-based detection means the defender must predict every variant; the attacker only needs to find one unpredicted variant.
4. **Capability-based security closes attack classes, not individual attacks.** A sandbox that denies `~/.aws/` access defeats Attacks 1, 2, 4, 5, and 6 simultaneously.
5. **Acknowledge residual risks publicly.** The honest "this is the limit of what regex can catch" is more trustworthy than "we caught everything."
6. **The CI layer matters.** Attack 4's cross-file composition gap is correctly pushed to PR-time analysis — that's defense-in-depth working as designed.

---

# Final Status

| Layer | Status | Coverage |
|---|---|---|
| Rule-based hooks (current) | 8/8 attacks patched | ~85% of known attack variants |
| Capability-based sandboxing | NOT IMPLEMENTED | Would close ~95% of attack classes |
| Filesystem immutability | NOT IMPLEMENTED | Would close guardrail self-destruction entirely |
| Behavioral audit | NOT IMPLEMENTED | Would detect novel attacks post-execution |
| Network egress control | NOT IMPLEMENTED | Would defeat most exfiltration |
| Cross-file static analysis | PARTIAL (in CI) | Attack 4 residual |

**Next action:** Begin Phase 4 (sandboxing) as the highest-impact architectural improvement. Even a basic macOS sandbox-exec profile or Linux bubblewrap wrapper would be a massive step forward from the current pure-hook approach.

---

# Competitive Analysis: GoPlus AgentGuard (2026-04-10)

Discovered a well-shipped competitor also called "AgentGuard" by GoPlus Security (MIT licensed, npm published, multi-platform). Despite the name collision, they solve a different problem for a different audience. Full analysis below.

## Feature Comparison

| Area | Your Framework | GoPlus AgentGuard | Winner |
|---|---|---|---|
| Target user | Engineering teams with compliance needs | Individual devs, Web3 users | Different markets |
| Deployment | install script + merge-based | npm install | GoPlus |
| Detection rules | 66 deny patterns + 18 advisory + content scanners | 24 detection rules | You (depth) |
| Red team tested | Yes — 8 attacks, 203 tests, documented residuals | Unknown / none public | You |
| Platform support | Claude Code | Claude Code, OpenClaw, Codex CLI, Gemini, Cursor, Copilot | GoPlus |
| CI/CD integration | Full: 3 agents, auto-fix, PR comments | None | You |
| Compliance mapping | ISO 27001, SOC 2, Korean AI Basic Act, EU AI Act | None | You |
| Audit trail | JSON-lines log, governance reports | Audit log, event log | Tie |
| Web3 / crypto protection | None | Wallet draining, unlimited approvals, reentrancy, flash loans | GoPlus |
| Health reporting | Text findings | Visual HTML report with lobster mascot | GoPlus |
| Scheduled scanning | No | "Daily Patrol" cron-based with 8 checks | GoPlus |
| Capability sandboxing | No (Phase 4 planned) | No | Tie |
| Trust registry for skills | No | Yes, capability-based access per skill | GoPlus |
| Open source / distribution | Free version shipped | MIT, npm published | GoPlus |
| Multi-language scanning | Python, Java, C/C++, JS in CI agents | JavaScript-centric | You |
| Protection level modes | No (single mode) | strict / balanced / permissive | GoPlus |

## Where GoPlus Wins

1. **Distribution** — `npm install` vs complex install.sh
2. **Platform breadth** — 6 AI tools supported vs 1
3. **User experience** — Visual HTML health report with mascot; shareable and memorable
4. **Web3 specificity** — Wallet draining / unlimited approvals / reentrancy detection
5. **Daily patrol** — Scheduled posture assessment via cron with 8 checks
6. **Skill scanning** — Scans AI skills/plugins at install time (attack vector not in your threat model)
7. **Shipping maturity** — npm package, docs, examples, roadmap with completed milestones, protection level modes

## Where You Win

1. **Depth of enforcement** — 8 hooks + 66 deny rules + content scanners + realpath + composition analysis is significantly more rigorous
2. **Adversarial testing** — 8-attack red team log with patches and documented residuals. GoPlus has zero public adversarial testing evidence.
3. **Compliance story** — ISO 27001, SOC 2, EU AI Act, Korean AI Basic Act mapping. GoPlus has zero compliance story.
4. **CI/CD pipeline integration** — Three agents on every PR with auto-fix. GoPlus is workstation-only.
5. **Multi-language coverage** — Python, Java, C/C++, JavaScript in CI agents.
6. **Documented threat model** — Red team log is a serious security artifact competitors can't replicate without redoing the work.

## Strategic Implications

### Honest verdict

GoPlus is a better product *today* for individual developers and Web3 users. They shipped faster, broader, and with better UX. However, they are **disqualified** for enterprise customers with compliance requirements:
- No compliance mapping
- No CI/CD governance
- No adversarial testing evidence
- No multi-language scanning
- No audit trail designed for auditors

This means the market is segmented, not contested. You and GoPlus are solving different problems for different buyers.

### Positioning shift (already partially done)

Stop competing on "AI agent security" as a general category — GoPlus owns that narrative with their lobster mascot and npm distribution. Own the **enterprise compliance** angle instead:

> "We map Claude Code activity to ISO 27001 Annex A controls, generate audit-ready documentation, and integrate with your CI/CD pipeline."

Nobody else in the AI agent security space is saying this. It's an open lane.

### Market segmentation pitch

> "GoPlus AgentGuard protects individual developers and Web3 users. [Your renamed product] protects engineering organizations. If you have a compliance officer, you need us. If you're a solo dev using Claude Code for crypto projects, use GoPlus."

This turns a name-collision competitor into a market-clarifier.

## TODO Items from Competitive Analysis

### Done
- [x] Renamed the product (no longer AgentGuard → OpSentry) — 2026-04-09
- [x] Shipped free version publicly — `opsight-intelligence/opsentry` (public)
- [x] Rebranded all docs, CI workflows, CLI, Homebrew, GitHub Action — 2026-04-10
- [x] Red-team hardened all 8 hooks — full-path bypass, UPDATE/WHERE bug, no-space flags, encoding tools, PII format evasion, 155 tests (67 red-team) — 2026-04-10
- [x] GitHub release v1.7.0 with hardening — 2026-04-10
- [x] Homebrew tap — `opsight-intelligence/homebrew-opsentry` — 2026-04-10
- [x] GitHub Action — `opsight-intelligence/opsentry-action` tagged v1 — 2026-04-10
- [ ] Add red team log to the repo / public docs — in progress today

### Borrow from GoPlus (product improvements)

- [ ] **Visual health report** — build a dashboard/HTML report equivalent to GoPlus's lobster report. Not a mascot (don't copy), but a visual summary developers want to share. Ideas: weekly email digest with charts, "guardrail health score" dashboard, PDF compliance summary.
- [ ] **Protection level modes** — implement `strict` / `balanced` / `permissive` modes. Currently the framework is single-mode. Balanced should be the default; strict for regulated environments; permissive for solo devs trying it out.
- [x] ~~**Package distribution**~~ — pip package built (`pip install opsentry`), Homebrew tap live, GitHub Action published. npm TBD.
- [ ] **Skill scanning** — add a hook or CI check that scans AI skills/plugins/extensions at install time. This attack vector isn't in the current threat model but GoPlus shows it's real.
- [ ] **Scheduled posture assessment** — add a `verify.sh --audit` mode that runs periodically (cron) and produces a report. GoPlus calls this "Daily Patrol" — you could call it "Compliance Patrol" or "Daily Audit."
- [ ] **Multi-platform support** — research what hooks exist in Cursor, Copilot, Gemini, Codex CLI. Your hook-based approach is Claude-specific, but the principles (content scanning, pattern detection, CI integration) translate. Start with a comparison doc showing what's possible on each platform. (Also in TODO.md Phase 6)
- [ ] **Trust registry** — GoPlus has capability-based access per skill. Consider an equivalent concept for your framework: per-project or per-developer trust levels that gate certain operations.

### Positioning actions

- [ ] **Rewrite public README** — lead with the enterprise compliance story, not the rule count. Open with "The only AI coding agent security framework with ISO 27001 and SOC 2 audit-ready documentation."
- [ ] **Publish the red team log** — this is your most unique asset. Add it to the public repo as `docs/red-team-log.md`. Link to it from the README and landing page.
- [ ] **Add market segmentation to pitch** — "If you have a compliance officer, you need us" is a clearer qualifying statement than "we protect AI agents."
- [ ] **Add a compliance comparison table** to the landing page: you vs GoPlus vs Semgrep vs Snyk, with rows for ISO 27001 mapping, SOC 2 mapping, Korean AI Basic Act, CI/CD integration, red team evidence. Make the gaps visible.
- [ ] **Write a blog post** — "Why we red-teamed our own AI agent guardrails and what we learned." Link to the red team log. This becomes your top lead-generation content. (3 other blog posts already drafted in `docs/blog/`)
- [ ] **Add contact link for enterprise** — "Talk to us about ISO 27001 certification" CTA. Enterprise buyers self-select on compliance language.

### Technical improvements inspired by GoPlus

- [ ] **Adapter abstraction layer** — GoPlus has a unified decision engine with platform-specific adapters (Claude Code, OpenClaw). Consider refactoring your hooks to separate the decision logic from the platform-specific hook invocation. This would make future multi-platform support easier.
- [ ] **Audit log attack pattern analysis** — GoPlus's patrol analyzes audit logs for repeat denials and attack patterns. Extend your `guardrail-blocks.log` analysis to detect patterns like "same skill triggered 3+ denials" or "exfiltration attempts in last 24h."
- [ ] **Baseline integrity checks** — GoPlus verifies config baseline integrity. Your `verify.sh` does this for hook files; extend it to settings.json and CLAUDE.md with hash comparison.
- [ ] **Network exposure check** — add a check for dangerous ports bound to 0.0.0.0 (Redis, Docker API, MySQL) in the CI governance agent.

## Key Insight from the Comparison

The existence of a well-shipped competitor in the same space **validates the market**, it doesn't invalidate your work. GoPlus is proof that companies are worried about AI agent security enough to pay for tools.

Your advantage is not "more features" — it's **depth + compliance + adversarial testing evidence**. These are enterprise-grade differentiators that GoPlus cannot match without rebuilding from scratch. You can borrow their UX and distribution ideas faster than they can borrow your compliance story.

The next 30 days should be about closing the distribution and UX gap while maintaining the depth and compliance lead.

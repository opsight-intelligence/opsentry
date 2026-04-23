# OpSentry Community — Gap Analysis vs Prompt Security (SentinelOne)

Based on Prompt Security's Korean sales material, L1 deck, datasheet, and retail solution brief.
Purpose: Identify baseline security gaps in the **community edition** of OpSentry.

> **Tier scope:** This document tracks gaps relevant to the free/open-source OpSentry.
> Enterprise-only items (SIEM/XDR integration, dynamic agent risk scoring, red-team-to-runtime
> automation, multi-tool adapters) live in the **OpSentry Pro** gap analysis, not here.

---

## Core Positioning

> **Prompt Security monitors what goes into AI tools.
> OpSentry monitors what AI agents do with your codebase.**

Stay in the developer-environment and CI lane. Do not drift into browser extensions,
customer-facing LLM output filtering, or deepfake/impersonation defense.

Gartner category to claim: **AI TRiSM**. Narrower and more defensible than "AI security."

Useful external data point: *~1.6% of all AI prompts contain a policy violation*
(Prompt Security retail brief, 2026).

---

## Features They Have That We Don't

### 1. Shadow MCP Server Detection
**What they do:** Detect unauthorized MCP (Model Context Protocol) servers and agent
deployments that bypass existing security tools. *"Surface every AI agent, MCP server,
and shadow deployment... including those spun up without IT knowledge."*

**Do we need this?** **YES — highest priority.** MCP is the single biggest emerging
attack surface for developer-tool AI, and no open-source project currently addresses it.

**What we have:** Nothing. MCP servers can give Claude Code access to external tools,
databases, APIs without going through our hooks.

**Implementation idea:**
- [ ] Scan for MCP server configurations in project files (`.mcp.json`, `mcp_config.json`,
      Claude Code MCP settings)
- [ ] Maintain an allowlist of approved MCP servers
- [ ] Flag unknown/unauthorized MCP servers in Compliance Patrol
- [ ] Hook: detect Claude Code connecting to non-allowlisted MCP endpoints

**Priority:** **P0** — genuine security gap, strong community differentiator.

---

### 2. Red-Team Framework as Headline Feature
**What they do:** Prompt Security ships "AI Red Teaming" as a named product line —
*"expose prompt injection, jailbreaks, data poisoning... risk-scored findings with
remediation guidance."*

**Do we need this?** **YES — and we already have most of it.** `redteam-loop/` plus
`red-team-log.md` is already further along than most competitors. The gap is
**visibility**, not implementation.

**What we have:** `redteam-loop/` testing framework, documented attack log (8 attacks
launched, 8 patched, 203 tests).

**Implementation idea:**
- [ ] Promote red-team framework to a top-level README section (currently buried in docs)
- [ ] Add `opsentry redteam` CLI entrypoint that runs the loop end-to-end
- [ ] Publish the attack log as a public artifact (evidence of hardening)
- [ ] Include round summaries in CI: "Red-team round N passed against current hooks"

**Priority:** **P0** — zero engineering cost, large marketing win.

---

### 3. Shadow AI Tool Discovery
**What they do:** Detect and monitor all AI tools in use across the organization —
including unsanctioned ones.

**Do we need this?** YES — valuable for individuals and small teams too.

**Implementation idea:**
- [ ] Scan developer machines for installed AI tools (Claude Code, Copilot, Cursor,
      Windsurf, Codeium, ChatGPT desktop, Gemini)
- [ ] Report which tools are present, which have guardrails installed, which don't
- [ ] Add to Compliance Patrol: "3 tools installed; 1 without guardrails"

**Priority:** Medium. Useful at any tier; kept in community so the free edition can
at least surface shadow AI.

---

### 4. Prompt/Response Logging (Opt-In, Local)
**What they do:** Centrally log and visualize entire prompt, response, and attachment
history across all AI tools. Auditable, searchable.

**Do we need this?** PARTIALLY. Community tier should offer **local** opt-in logging.
Central aggregation / SIEM forwarding belongs in Pro.

**What we have:** `guardrail-blocks.log` logs blocked actions only.

**Implementation idea:**
- [ ] Add optional full session logging (all tool calls, not just blocks) to a local
      JSON-lines file
- [ ] Structured format: timestamp, tool, input hash, output hash, decision, user
- [ ] Opt-in flag (privacy concern — logging all prompts is sensitive)
- [ ] `opsentry logs --last 24h --filter blocked` viewer command

**Priority:** High. Pairs with Shadow MCP — detection without evidence is thin.

---

### 5. Data Masking / Auto-Anonymization
**What they do:** When sensitive data (PII, secrets, source code) is detected in a
prompt, automatically mask or redact it before it reaches the LLM.

**Do we need this?** YES — genuinely different from blocking.

**What we have:** We block writes containing PII. We don't mask — we reject entirely.

**Implementation idea:**
- [ ] Add masking mode alongside blocking: replace credit card number with
      `[REDACTED-CC]` and allow the write
- [ ] Configurable per protection level: strict = block, balanced = mask, permissive = warn
- [ ] Mask patterns: SSN → `XXX-XX-XXXX`, credit cards → `XXXX-XXXX-XXXX-1234`,
      emails → `user@[REDACTED]`, API keys → `sk-[REDACTED]`

**Priority:** Medium. Nice UX improvement; blocking is still more secure.

---

### 6. Employee Coaching / Non-Intrusive Guidance
**What they do:** *"Coach your employees on the safe use of AI tools with non-intrusive
explanations."*

**Do we need this?** YES — improves adoption, reduces "developers disable guardrails" risk.

**What we have:** Block messages say what was blocked but not always why or what to do instead.

**Implementation idea:**
- [ ] Improve block messages: what was blocked, why dangerous, what to do instead
- [ ] Example: *"Blocked: reading .env files directly. Use `os.environ.get('VAR_NAME')`
      to access environment variables safely. See: docs.opsentry.dev/secrets"*
- [ ] `--explain` flag for educational context

**Priority:** Medium. Improves DX and reduces pushback.

---

## Summary: Community Roadmap

### P0 (ship next)
- [ ] Shadow MCP server detection
- [ ] Red-team framework as headline feature (README promotion + CLI entrypoint)

### P1
- [ ] Opt-in local session logging with viewer command
- [ ] Improved block messages with educational guidance

### P2
- [ ] Shadow AI tool discovery
- [ ] Data masking mode

### Not community (see OpSentry Pro gap analysis)
- SIEM/XDR integration, syslog/webhook forwarding, CEF/LEEF formats
- Dynamic agent risk scoring
- Action-chaining detection
- Red-team-to-runtime hook auto-generation
- Multi-LLM adapters (Cursor, Copilot, Windsurf)
- Central log aggregation / SaaS dashboard
- Denial-of-Wallet cost controls

### Not our lane (at any tier)
- Browser-level prompt interception (Cymulate/Prompt Security do this; different architecture)
- Customer-facing LLM response filtering (application-layer concern)
- Deepfake/impersonation defense

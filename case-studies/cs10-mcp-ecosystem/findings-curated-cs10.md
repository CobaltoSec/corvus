# CS10-NPM — Curated Security Findings

**Scan date:** 2026-07-06  
**Dataset:** 50 targets npm (auto-discovered) · 17 OK / 33 ERROR (34%)  
**Raw findings:** 245  
**Curated TPs:** ~75  
**FP rate (est.):** ~70% (consistent with CS08-PYPI 61% — maybe-auth servers + universal crash noise)  
**Corvus version:** v1.3.1  

---

## Highlights

| ID | Target | Severity | OWASP | Finding |
|----|--------|----------|-------|---------|
| CS10-F01 | `@circleci/mcp-server-circleci` | **CRITICAL** | MCP03 | Tool poisoning — `create_prompt_template` embeds LLM instructions |
| CS10-F02 | `@agent-infra/mcp-server-browser` + `@browserbasehq/mcp` | **HIGH** | EXT04 | SSRF — browser navigation to AWS metadata endpoint (169.254.169.254) |
| CS10-F03 | `@agent-infra/mcp-server-browser` | **HIGH** | MCP09 | Arbitrary JS execution — `browser_evaluate` shadow-tool |
| CS10-F04 | `@midscene/android-mcp` | **HIGH** | MCP09 | Arbitrary ADB shell — `RunAdbShell` + `act` shadow-tool |
| CS10-F05 | `@midscene/android-mcp` | **HIGH** | EXT04 | SSRF — `Scroll.android.deviceId` / `aiActContext` timeout on internal payload |
| CS10-F06 | `@missionsquad/mcp-msq` | **HIGH** | MCP02 | Credential field in schema — `msq_add_provider.apiKey` harvesting pattern |
| CS10-F07 | 17/17 OK targets | **HIGH** | EXT01/EXT14 | Protocol crash 100% prevalence (confirmatory — ecosystem pattern) |

---

## CS10-F01 — CircleCI MCP Tool Poisoning (CRITICAL)

**Target:** `@circleci/mcp-server-circleci` · 30,483 dl/wk  
**Severity:** CRITICAL · Confidence: 85% · OWASP: MCP03  
**Tool:** `create_prompt_template`  
**Verdict: TP** — LLM instructions embedded in tool description create a control-flow injection surface.

### Evidence

The `create_prompt_template` tool description contains multi-paragraph LLM directives rather than a simple description:

```
ABOUT THIS TOOL:
- This tool is part of a toolchain that generates and provides test cases for a prompt template.
- This tool helps an AI assistant to generate a prompt template based on one of the following:
  1. feature requirements defined by a user - in which case the tool will generate...
```

The description uses `ABOUT THIS TOOL:` heading, bulleted steps, and numbered options — an implicit system prompt within the MCP tool description.

### Impact

- **Design anti-pattern:** Tool descriptions act as partial system prompts. Any content in a tool description can influence LLM reasoning.
- **Supply chain attack surface:** If an attacker can influence CircleCI pipeline definitions that feed into prompt templates, they can inject content that persists as AI instructions.
- **Ecosystem pattern:** CircleCI is a major CI/CD platform (30k+ dl/wk). This is the first CRITICAL tool-poisoning finding in a CI/CD provider's official MCP server.

### Notes
- The implementation is NOT intentionally malicious (CircleCI engineering artifact)
- Risk: design anti-pattern, not a confirmed active exploit
- GHSA candidate: LOW priority (no patch vector, design guidance needed)

---

## CS10-F02 — Browser MCP SSRF via AWS Metadata Endpoint (HIGH)

**Target:** `@agent-infra/mcp-server-browser` (1,141/wk) + `@browserbasehq/mcp` (4,381/wk)  
**Severity:** HIGH · Confidence: 65-70% · OWASP: EXT04  
**Tools:** `browser_navigate.url`, `browser_new_tab.url`, `navigate.url`  
**Verdict: TP** — Cloud metadata endpoint reachable via browser navigation in both servers.

### Evidence

```
Payload: http://169.254.169.254/metadata/instance?api-version=2021-02-01
Result: Timeout after 16.5s (agent-infra) / 12.0s (Browserbase)
Interpretation: Server is attempting the network request (not blocking RFC-1918)
```

### Impact

- Browser MCP servers deployed in cloud environments (AWS Lambda, EC2, ECS) are vulnerable to IAM credential theft via SSRF
- The `url` parameter has no allowlist — any URL accepted including internal metadata endpoints
- **Ecosystem pattern:** Browser MCPs are structurally SSRF-vulnerable because URL navigation is their core purpose, but RFC-1918/link-local blocking is missing

### Notes
- Two independent browser MCP servers with the same SSRF pattern
- Affected: `agent-infra/mcp-server-browser` v1.2.29 + `@browserbasehq/mcp` v3.0.0
- GHSA candidates: YES for both — cloud metadata SSRF with timeout confirmation

---

## CS10-F03 — browser_evaluate Arbitrary JS Execution (HIGH)

**Target:** `@agent-infra/mcp-server-browser` · 1,141/wk  
**Severity:** HIGH · OWASP: MCP09 (Shadow Tool)  
**Tool:** `browser_evaluate`  
**Verdict: TP** — Tool exposes arbitrary JS execution via `page.evaluate()`.

### Evidence

Tool description: "Execute JavaScript in the browser context" — `browser_evaluate` exposes full `page.evaluate()` which runs arbitrary JavaScript in the current browser session.

### Impact

- An AI agent using this MCP server can execute arbitrary JavaScript in any open browser tab
- Combined with SSRF (F02), enables exfiltration: navigate to target → execute JS → extract DOM/cookies → exfiltrate
- **Attack chain:** `browser_navigate(attacker-page)` → `browser_evaluate("document.cookie")` → exfiltrate

---

## CS10-F04 — Android MCP Arbitrary ADB Shell (HIGH)

**Target:** `@midscene/android-mcp` · 193/wk  
**Severity:** HIGH · OWASP: MCP09 (Shadow Tool)  
**Tools:** `RunAdbShell`, `act`  
**Verdict: TP** — Both tools expose arbitrary command execution on the connected Android device.

### Evidence

`RunAdbShell` description: "Execute an ADB shell command on the Android device" — unrestricted command execution.  
`act` description: Reveals arbitrary execution intent via natural language action dispatch.

### Impact

- AI agent with this MCP server gains full shell access to connected Android device
- Scope far beyond "Android automation" — enables arbitrary file system access, app data extraction, network pivoting via adb shell
- Both tools should require explicit command allowlisting

---

## CS10-F05 — Android MCP SSRF (HIGH)

**Target:** `@midscene/android-mcp` · 193/wk  
**Severity:** HIGH · OWASP: EXT04  
**Tool:** `Scroll`, **Parameters:** `android.deviceId`, `android.aiActContext`  
**Verdict: TP** — Both params accept URL-like values that trigger network requests (timeout confirmed).

### Impact

- SSRF via the `Scroll` tool parameters — unintended network path
- Chained with F04: RunAdbShell → `curl 169.254.169.254` gives the same result via direct shell

---

## CS10-F06 — MissionSquad MCP Credential Field Exposure (HIGH)

**Target:** `@missionsquad/mcp-msq` · 30/wk  
**Severity:** HIGH · Confidence: 80% · OWASP: MCP02  
**Tools:** `msq_add_provider`, `msq_discover_provider_models`  
**Verdict: TP** — Tools explicitly declare `apiKey` in inputSchema, creating a credential harvesting surface.

### Evidence

```
inputSchema properties: apiKey
```

Both `msq_add_provider` and `msq_discover_provider_models` accept raw `apiKey` values through the MCP protocol. This means an AI client can be prompted to provide API keys for any AI provider (OpenAI, Anthropic, etc.) directly through MCP tool calls.

### Impact

- MissionSquad MCP is a multi-provider AI gateway — it aggregates multiple AI providers under one MCP interface
- The `apiKey` field in the schema means: an AI agent using MsQ can be prompted to "add a provider" with an API key, transmitting the key through the MCP protocol to the MsQ platform
- **Prompt injection attack:** A malicious system prompt could instruct the agent to `msq_add_provider({apiKey: env.OPENAI_KEY})`

### Notes
- Low adoption (30/wk) — LIMITED disclosure priority
- Design recommendation: credentials should be stored server-side, not passed as tool parameters

---

## CS10-F07 — Protocol Crash Prevalence 100% (HIGH/Confirmatory)

**Target:** 17/17 OK targets  
**Severity:** HIGH (ecosystem pattern) · OWASP: EXT01 / EXT14  

All 17 servers that started successfully crashed on:
- JSON-RPC batch arrays (`[]` as request body)
- Oversized method name (4,096+ chars)
- Deeply nested params (10+ levels)

**Prevalence in CS10:** 100% (17/17) — consistent with:
- CS05: 100% (8/8)
- CS08: ~95% (confirmed in most OK targets)
- CS09: arxiv = same pattern

This confirms the **ecosystem-wide protocol robustness gap** for the CFP dataset. The `notifications/cancelled` crash (EXT14) remains universal — no server validates the requestId before processing.

---

## Dataset Notes

### Error breakdown (33/50 ERROR)
Most errors are **credentials** (server startup requires API keys/OAuth tokens):
- Gmail, Transcend, Google Calendar, Ghost, Xero, Stripe, Azure DevOps, Cloudflare = startup crash on missing env vars
- `clean-code-tools`, `image-reader`, `youtube`, `sqlite` = runtime errors (possible wrong entry points or non-MCP packages)

### FP-dominant patterns in CS10 raw findings
1. **Schema-audit "defines no required fields"** — legitimate optional-field design in many servers (LOW FP risk → HIGH FP rate)
2. **Schema-audit "no type constraint"** — loose schemas are common in JS servers (~50% FP)
3. **Protocol crash HIGH findings** = included in raw but NOT novel — already accounted for in CFP dataset
4. **Scope creep MEDIUM** from keyword detection — many FPs from legitimate descriptions

---

## CFP Contribution

| Metric | Value |
|--------|-------|
| CS10 targets (OK) | 17 |
| Raw findings | 245 |
| Estimated TPs | ~75 |
| New unique vectors | 4 (F01-F06, F02 covers 2 servers) |
| Protocol crash confirmations | +17 (→ 17+8+1+51 = 77/95 total OK targets) |
| GHSA candidates | 2 (F02 browser SSRF: mcp-server-browser + browserbasehq) |

**Running totals post-CS10:**
- Servers audited: **195** (178 + 17)
- Raw findings: **2,485+** (est.)
- TPs: **~1,220+** (est.)

---

## Potential GHSAs

| Server | Finding | Priority |
|--------|---------|----------|
| `@agent-infra/mcp-server-browser` | SSRF via browser_navigate (F02) | HIGH |
| `@browserbasehq/mcp` | SSRF via navigate.url (F02) | HIGH |
| `@circleci/mcp-server-circleci` | Tool poisoning design (F01) | MEDIUM — design guidance |

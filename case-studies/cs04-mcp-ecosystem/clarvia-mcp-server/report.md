# Corvus Security Scan Report

**Target:** `npx -y clarvia-mcp-server`
**Transport:** stdio
**Date:** 2026-07-03 16:57:31
**Duration:** 113.4s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | Clarvia AEO Scanner |
| Version | 1.2.8 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 17 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 3 |
| LOW | 1 |
| INFO | 2 |


**Total:** 7 finding(s)

---

## Findings



### CORVUS-001 — Scope Creep — 'clarvia_submit_feedback' claims unrestricted access scope

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `clarvia_submit_feedback` |
| Parameter | `—` |
| Confidence | 85% |

Tool 'clarvia_submit_feedback' description contains a broad-scope claim: 'all users'. Unrestricted scope tools risk being exploited for lateral movement or privilege escalation in an MCP session.



**Evidence:**
```
Report the outcome after using a tool (success / failure / partial) to contribute to Clarvia's reliability dataset. Use after every agent tool invocation to help build community-driven quality signals. Accepts optional latency and error details. Improves future agent tool selection accuracy for all 
```


**Remediation:** Scope tools to the minimum necessary access. Replace 'any path' / 'all files' with explicit allowlists. Validate and restrict inputs server-side.

---

### CORVUS-002 — 'clarvia_top_picks' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `clarvia_top_picks` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-003 — Tool Chaining — 'clarvia_gate_check' directs LLM to call clarvia_find_alternatives

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT06 |
| Tool | `clarvia_gate_check` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'clarvia_gate_check' description references tool(s) 'clarvia_find_alternatives' from the same server using imperative language. This pattern can force an LLM into an unintended call chain or manufacture urgency to invoke a privileged tool.



**Evidence:**
```
Before calling any external API or MCP, use this to check if it is agent-ready. Returns AGENT_NATIVE / AGENT_FRIENDLY / AGENT_POSSIBLE / AGENT_HOSTILE with a boolean pass/fail. Call this first — if the service scores below your threshold, use clarvia_find_alternatives to get a better-rated replaceme
```


**Remediation:** Tool descriptions should describe what the tool does — not instruct the LLM on what other tools to call. Remove cross-tool directives and let the caller decide the execution order.

---

### CORVUS-004 — initialize accepts protocol version downgrade

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP07 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 75% |

The server accepted initialize with arbitrary protocol versions: ['9999-99-99', '2030-01-01', '1.0', '2024-01-01', '""', '0.1']. The server also accepted far-future versions, indicating no version validation at all. Servers should reject versions outside their supported range to prevent feature-downgrade attacks.



**Evidence:**
```
Accepted versions: ['9999-99-99', '2030-01-01', '1.0', '2024-01-01', '""', '0.1']
```


**Remediation:** Validate protocolVersion against a supported range. Return a JSON-RPC error for versions outside that range.

---

### CORVUS-005 — Null request ID accepted — JSON-RPC spec violation

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 60% |

The server accepted a request with id=null and returned a result. Per JSON-RPC 2.0, null IDs are reserved for notifications (no response expected). Accepting them may cause response routing bugs in complex orchestration scenarios.




**Remediation:** Reject requests with null id values; treat them as notifications.

---

### CORVUS-006 — Protocol crash — string params caused server disconnect

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 65% |

Sending a tools/call request where params is a string (not an object) caused the server to crash or disconnect. The JSON-RPC spec requires params to be an array or object.


**Payload:**
```
{"method":"tools/call","params":"not-an-object"}
```



**Remediation:** Validate params type (must be object or array) before processing. Return -32600 (Invalid Request) for wrong types.

---

### CORVUS-007 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

15 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---



*Generated by [Corvus](https://github.com/CobaltoSec/corvus)*
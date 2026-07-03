# Corvus Security Scan Report

**Target:** `npx -y @taiga-ui/mcp@latest --source-url=https://taiga-ui.dev/llms-full.txt`
**Transport:** stdio
**Date:** 2026-07-03 13:18:02
**Duration:** 77.2s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | taiga-ui-mcp |
| Version | 0.2.3 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 4 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 3 |
| LOW | 2 |
| INFO | 1 |


**Total:** 7 finding(s)

---

## Findings



### CORVUS-001 — 'get_list_components' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_list_components` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-002 — Response Flooding — 'get_list_components' returns oversized response

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP10 |
| Tool | `get_list_components` |
| Parameter | `—` |
| Confidence | 85% |

Tool 'get_list_components' returned 31,017 bytes (threshold: 8,192 bytes). Large responses can overflow LLM context windows, push out system prompts, or cause denial-of-service in agent pipelines.



**Evidence:**
```
31,017 bytes — preview: {
  "items": [
    {
      "id": "components/Accordion",
      "name": "Accordion",
      "category": "components",
      "package": "KIT",
      "type": "components"
    },
    {
      "id": "compone
```


**Remediation:** Paginate or cap tool responses. Never return unbounded data. Aim for responses under 4 KB to preserve LLM context budget.

---

### CORVUS-003 — Response Flooding — 'get_list_components' returns highly repetitive content

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP10 |
| Tool | `get_list_components` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'get_list_components' response contains a phrase repeated ≥15 times. Repetitive content can be used to anchor specific instructions into LLM memory or exhaust context budget with low-information noise.



**Evidence:**
```
{
  "items": [
    {
      "id": "components/Accordion",
      "name": "Accordion",
      "category": "components",
      "package": "KIT",
      "type": "components"
    },
    {
      "id": "components/ActionBar",
      "name": "ActionBar",
      "category": "components",
      "package": "KIT",
 
```


**Remediation:** Deduplicate response data. Avoid returning the same value or phrase more than a handful of times in a single response.

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

2 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---



*Generated by [Corvus](https://github.com/CobaltoSec/corvus)*
# Corvus Security Scan Report

**Target:** `npx -y marketnow-mcp`
**Transport:** stdio
**Date:** 2026-07-03 16:55:40
**Duration:** 58.5s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | marketnow |
| Version | 1.0.0 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 5 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 3 |
| LOW | 2 |
| INFO | 1 |


**Total:** 8 finding(s)

---

## Findings



### CORVUS-001 — Supply Chain — '@modelcontextprotocol/sdk' has high vulnerability (no CVE assigned)

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP04 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 65% |

Package '@modelcontextprotocol/sdk' (dependency of 'marketnow-mcp') has a known high vulnerability. Solo aplicable a servidores npm vía stdio. HTTP transport: no analizable.



**Evidence:**
```
@modelcontextprotocol/sdk@<=1.25.1 — no CVE assigned
```


**Remediation:** Update '@modelcontextprotocol/sdk' to a patched version.

---

### CORVUS-002 — 'search_skills' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `search_skills` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-003 — Response Flooding — 'list_categories' returns oversized response

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP10 |
| Tool | `list_categories` |
| Parameter | `—` |
| Confidence | 85% |

Tool 'list_categories' returned 14,214 bytes (threshold: 8,192 bytes). Large responses can overflow LLM context windows, push out system prompts, or cause denial-of-service in agent pipelines.



**Evidence:**
```
14,214 bytes — preview: [
  {
    "name": "AI/ML",
    "slug": "ai-ml",
    "count": 1980,
    "url": "https://marketnow.site/registry?cat=ai-ml",
    "bulk_imported": false,
    "disclosure": null
  },
  {
    "name": "Deve
```


**Remediation:** Paginate or cap tool responses. Never return unbounded data. Aim for responses under 4 KB to preserve LLM context budget.

---

### CORVUS-004 — Response Flooding — 'list_categories' returns highly repetitive content

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP10 |
| Tool | `list_categories` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'list_categories' response contains a phrase repeated ≥15 times. Repetitive content can be used to anchor specific instructions into LLM memory or exhaust context budget with low-information noise.



**Evidence:**
```
[
  {
    "name": "AI/ML",
    "slug": "ai-ml",
    "count": 1980,
    "url": "https://marketnow.site/registry?cat=ai-ml",
    "bulk_imported": false,
    "disclosure": null
  },
  {
    "name": "Developer Tools",
    "slug": "developer-tools",
    "count": 1882,
    "url": "https://marketnow.site/r
```


**Remediation:** Deduplicate response data. Avoid returning the same value or phrase more than a handful of times in a single response.

---

### CORVUS-005 — initialize accepts protocol version downgrade

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

### CORVUS-006 — Null request ID accepted — JSON-RPC spec violation

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

### CORVUS-007 — Protocol crash — string params caused server disconnect

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

### CORVUS-008 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

3 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---



*Generated by [Corvus](https://github.com/CobaltoSec/corvus)*
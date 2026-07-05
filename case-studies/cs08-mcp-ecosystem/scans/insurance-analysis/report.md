# Corvus Security Scan Report

**Target:** `uvx insurance-analysis-mcp`
**Transport:** stdio
**Date:** 2026-07-05 20:24:24
**Duration:** 49.6s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | insurance-analysis-mcp |
| Version | 1.28.1 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 2 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 3 |
| LOW | 6 |
| INFO | 1 |


**Total:** 10 finding(s)

---

## Findings



### CORVUS-001 — High entropy description in 'analyze_customer_retention_value'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `analyze_customer_retention_value` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-002 — Parameter 'policy_data' in 'analyze_customer_retention_value' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `analyze_customer_retention_value` |
| Parameter | `policy_data` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'policy_data'.

---

### CORVUS-003 — Parameter 'claim_data' in 'analyze_customer_retention_value' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `analyze_customer_retention_value` |
| Parameter | `claim_data` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'claim_data'.

---

### CORVUS-004 — 'analyze_customer_retention_value' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `analyze_customer_retention_value` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

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

### CORVUS-006 — initialize accepts type-confused protocolVersion (integer instead of string)

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP07 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 65% |

The server accepted an initialize request where protocolVersion was an integer (42) instead of a string. Strict type checking prevents parser confusion and unexpected coercion behavior.



**Evidence:**
```
protocolVersion: 42 (integer) → server returned serverInfo
```


**Remediation:** Validate that protocolVersion is a string before processing.

---

### CORVUS-007 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

1 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---

### CORVUS-008 — Server accepts path traversal cursor without validation

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT13 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 65% |

tools/list accepted cursor='../../../../etc/passwd' and returned a result instead of rejecting it. This may indicate missing cursor validation.


**Payload:**
```
../../../../etc/passwd
```



**Remediation:** Validate cursor values; reject non-opaque or path-like cursor strings.

---

### CORVUS-009 — Null request ID accepted — JSON-RPC spec violation

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

### CORVUS-010 — Protocol crash — string params caused server disconnect

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



*Generated by [Corvus](https://github.com/CobaltoSec/corvus)*
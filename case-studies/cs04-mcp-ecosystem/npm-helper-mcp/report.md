# Corvus Security Scan Report

**Target:** `npx -y @pinkpixel/npm-helper-mcp`
**Transport:** stdio
**Date:** 2026-07-03 16:26:59
**Duration:** 68.1s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | npm-helper-mcp |
| Version | 2.0.5 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 10 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 5 |
| INFO | 4 |


**Total:** 12 finding(s)

---

## Findings



### CORVUS-001 — 'check_updates' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `check_updates` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-002 — 'upgrade_packages' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `upgrade_packages` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-003 — 'resolve_conflicts' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `resolve_conflicts` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-004 — Injection reflected — 'get_package_versions.packageName'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `get_package_versions` |
| Parameter | `packageName` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: generic_string).


**Payload:**
```
null
```


**Evidence:**
```
📦 null
Available versions (newest first):
2.0.0, 1.0.1, 0.0.0
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-005 — Injection reflected — 'get_package_details.packageName'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `get_package_details` |
| Parameter | `packageName` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: generic_string).


**Payload:**
```
null
```


**Evidence:**
```
{
  "name": "null",
  "description": "Null generator library",
  "dist-tags": {
    "latest": "2.0.0"
  },
  "maintainers": [
    {
      "name": "qodeninja",
      "email": "qodeninja@outlook.com"
    }
  ],
  "repository": {
    "type": "git",
    "url": "git@qodeparty-gh:qodeparty/null.git"
  },

```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-006 — 'search_npm' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `search_npm` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-007 — 'get_package_versions' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_package_versions` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-008 — 'get_package_details' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_package_details` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-009 — Protocol crash — oversized method name caused transport failure

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 80% |

The server failed to respond to a request with an 8192-byte method name. A robust server should return a JSON-RPC error, not disconnect or crash.


**Payload:**
```
'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...' (8192 bytes)
```



**Remediation:** Add input length validation at the JSON-RPC parsing layer. Return -32700 (parse error) or -32600 (invalid request) for malformed inputs.

---

### CORVUS-010 — Protocol crash — deeply nested params caused server disconnect

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 70% |

Sending a tools/call request with 50-level nested params caused the server to disconnect or crash. Deep nesting can cause stack overflows or excessive memory use in recursive JSON parsers.


**Payload:**
```
tools/call {arguments: {x: {x: {x: ... (50 levels)}}}}
```



**Remediation:** Limit JSON object nesting depth at parse time (recommended: ≤32 levels). Return -32700 (Parse error) for inputs exceeding the depth limit.

---

### CORVUS-011 — Protocol crash — string params caused server disconnect

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

### CORVUS-012 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

10 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---



*Generated by [Corvus](https://github.com/CobaltoSec/corvus)*
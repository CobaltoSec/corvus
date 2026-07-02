# Corvus Security Scan Report

**Target:** `npx -y @regle/mcp-server`
**Transport:** stdio
**Date:** 2026-07-02 14:53:37
**Duration:** 64.8s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | regle-mcp-server |
| Version | 1.28.3 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 11 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 1 |
| MEDIUM | 4 |
| LOW | 16 |
| INFO | 0 |


**Total:** 22 finding(s)

---

## Findings



### CORVUS-001 — 'regle-list-documentation' has no description

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `regle-list-documentation` |
| Parameter | `—` |
| Confidence | 80% |

Tools without descriptions cannot be audited for hidden intent.




**Remediation:** Add a clear, concise description to every tool.

---

### CORVUS-002 — 'regle-get-documentation' has no description

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `regle-get-documentation` |
| Parameter | `—` |
| Confidence | 80% |

Tools without descriptions cannot be audited for hidden intent.




**Remediation:** Add a clear, concise description to every tool.

---

### CORVUS-003 — 'regle-get-usage-guide' has no description

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `regle-get-usage-guide` |
| Parameter | `—` |
| Confidence | 80% |

Tools without descriptions cannot be audited for hidden intent.




**Remediation:** Add a clear, concise description to every tool.

---

### CORVUS-004 — 'regle-get-vuelidate-migration-guide' has no description

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `regle-get-vuelidate-migration-guide` |
| Parameter | `—` |
| Confidence | 80% |

Tools without descriptions cannot be audited for hidden intent.




**Remediation:** Add a clear, concise description to every tool.

---

### CORVUS-005 — 'regle-search-documentation' has no description

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `regle-search-documentation` |
| Parameter | `—` |
| Confidence | 80% |

Tools without descriptions cannot be audited for hidden intent.




**Remediation:** Add a clear, concise description to every tool.

---

### CORVUS-006 — 'regle-list-rules' has no description

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `regle-list-rules` |
| Parameter | `—` |
| Confidence | 80% |

Tools without descriptions cannot be audited for hidden intent.




**Remediation:** Add a clear, concise description to every tool.

---

### CORVUS-007 — 'regle-get-rule-reference' has no description

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `regle-get-rule-reference` |
| Parameter | `—` |
| Confidence | 80% |

Tools without descriptions cannot be audited for hidden intent.




**Remediation:** Add a clear, concise description to every tool.

---

### CORVUS-008 — 'regle-list-validation-properties' has no description

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `regle-list-validation-properties` |
| Parameter | `—` |
| Confidence | 80% |

Tools without descriptions cannot be audited for hidden intent.




**Remediation:** Add a clear, concise description to every tool.

---

### CORVUS-009 — 'regle-list-helpers' has no description

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `regle-list-helpers` |
| Parameter | `—` |
| Confidence | 80% |

Tools without descriptions cannot be audited for hidden intent.




**Remediation:** Add a clear, concise description to every tool.

---

### CORVUS-010 — 'regle-get-helper-reference' has no description

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `regle-get-helper-reference` |
| Parameter | `—` |
| Confidence | 80% |

Tools without descriptions cannot be audited for hidden intent.




**Remediation:** Add a clear, concise description to every tool.

---

### CORVUS-011 — 'regle-get-api-reference' has no description

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `regle-get-api-reference` |
| Parameter | `—` |
| Confidence | 80% |

Tools without descriptions cannot be audited for hidden intent.




**Remediation:** Add a clear, concise description to every tool.

---

### CORVUS-012 — Injection reflected — 'regle-list-documentation.category'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `regle-list-documentation` |
| Parameter | `category` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: sql).


**Payload:**
```
' OR '1'='1
```


**Evidence:**
```
{
  "message": "Available Regle documentation pages",
  "category": "' OR '1'='1",
  "count": 0,
  "docs": []
}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-013 — Injection reflected — 'regle-search-documentation.query'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `regle-search-documentation` |
| Parameter | `query` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: sql).


**Payload:**
```
' OR '1'='1
```


**Evidence:**
```
{
  "query": "' OR '1'='1",
  "resultCount": 0,
  "results": [],
  "suggestions": [
    "advanced-usage",
    "general",
    "common-usage",
    "core-concepts",
    "rules",
    "examples",
    "integrations",
    "introduction",
    "troubleshooting",
    "typescript"
  ]
}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-014 — Token Exposure — credential in response in 'regle-list-rules'

| Field | Value |
|-------|-------|
| Severity | **CRITICAL** |
| OWASP | MCP01 |
| Tool | `regle-list-rules` |
| Parameter | `—` |
| Confidence | 85% |

Tool response contains credential in response.



**Evidence:**
```
{
  "title": "Built-in Rules",
  "package": "@regle/rules",
  "count": 51,
  "rules": [
    {
      "name": "alpha",
      "description": "-  "
    },
    {
      "name": "alphaNum",
      "description": "-  "
    },
    {
      "name": "atLeastOne",
      "description": "-   - Optional list of keys to check. If not provided, checks if the object has at least one filled property."
    },
    {
   
```


**Remediation:** Strip sensitive data from tool responses. Never return raw environment variables, credentials, or internal paths.

---

### CORVUS-015 — 'regle-list-documentation' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `regle-list-documentation` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-016 — 'regle-search-documentation' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `regle-search-documentation` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-017 — Response Flooding — 'regle-list-documentation' returns highly repetitive content

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP10 |
| Tool | `regle-list-documentation` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'regle-list-documentation' response contains a phrase repeated ≥15 times. Repetitive content can be used to anchor specific instructions into LLM memory or exhaust context budget with low-information noise.



**Evidence:**
```
{
  "message": "Available Regle documentation pages",
  "category": "all",
  "count": 47,
  "docs": [
    {
      "id": "advanced-usage-extend-properties",
      "title": "Extend properties"
    },
    {
      "id": "advanced-usage-global-config",
      "title": "Global configuration"
    },
    {
 
```


**Remediation:** Deduplicate response data. Avoid returning the same value or phrase more than a handful of times in a single response.

---

### CORVUS-018 — Response Flooding — 'regle-list-rules' returns highly repetitive content

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP10 |
| Tool | `regle-list-rules` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'regle-list-rules' response contains a phrase repeated ≥15 times. Repetitive content can be used to anchor specific instructions into LLM memory or exhaust context budget with low-information noise.



**Evidence:**
```
{
  "title": "Built-in Rules",
  "package": "@regle/rules",
  "count": 51,
  "rules": [
    {
      "name": "alpha",
      "description": "- `allowSymbols?: MaybeRefOrGetter<boolean>`"
    },
    {
      "name": "alphaNum",
      "description": "- `allowSymbols?: MaybeRefOrGetter<boolean>`"
    },
 
```


**Remediation:** Deduplicate response data. Avoid returning the same value or phrase more than a handful of times in a single response.

---

### CORVUS-019 — Response Flooding — 'regle-list-validation-properties' returns oversized response

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP10 |
| Tool | `regle-list-validation-properties` |
| Parameter | `—` |
| Confidence | 85% |

Tool 'regle-list-validation-properties' returned 9,318 bytes (threshold: 8,192 bytes). Large responses can overflow LLM context windows, push out system prompts, or cause denial-of-service in agent pipelines.



**Evidence:**
```
9,318 bytes — preview: {
  "id": "core-concepts-validation-properties",
  "title": "Validation properties",
  "category": "core-concepts",
  "content": "# Validation properties\n\nValidation properties are computed values o
```


**Remediation:** Paginate or cap tool responses. Never return unbounded data. Aim for responses under 4 KB to preserve LLM context budget.

---

### CORVUS-020 — initialize accepts protocol version downgrade

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

### CORVUS-021 — Null request ID accepted — JSON-RPC spec violation

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

### CORVUS-022 — Protocol crash — string params caused server disconnect

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
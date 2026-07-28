# Corvus Security Scan Report

**Target:** `https://sniff.world/api/mcp`
**Transport:** http
**Date:** 2026-07-28 17:01:58
**Duration:** 25.2s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | sniff |
| Version | 1.0.0 |
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
| HIGH | 0 |
| MEDIUM | 5 |
| LOW | 2 |
| INFO | 2 |


**Total:** 9 finding(s)

---

## Findings



### CORVUS-001 — Tool Chaining — 'search_diseases' directs LLM to call lookup_disease

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT06 |
| Tool | `search_diseases` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'search_diseases' description references tool(s) 'lookup_disease' from the same server using imperative language. This pattern can force an LLM into an unintended call chain or manufacture urgency to invoke a privileged tool.



**Evidence:**
```
Search the canine disease catalogue by free text and return ranked candidate diseases (name + OMIA id + canonical sniff.world URL). Use this to find the exact disease before calling lookup_disease, or to enumerate diseases matching a term. Dog-only.
```


**Remediation:** Tool descriptions should describe what the tool does — not instruct the LLM on what other tools to call. Remove cross-tool directives and let the caller decide the execution order.

---

### CORVUS-002 — Injection reflected — 'lookup_disease.query'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `lookup_disease` |
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
  "found": false,
  "message": "No confident single match for \"' OR '1'='1\". Try search_diseases, or a different term. Coverage is dog-only.",
  "candidates": []
}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-003 — Token Exposure — server version disclosure in HTTP response headers

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | MCP01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 75% |

HTTP response header 'server: cloudflare' discloses internal information.



**Evidence:**
```
server: cloudflare
```


**Remediation:** Remove the 'server' response header in production.

---

### CORVUS-004 — 'lookup_disease' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `lookup_disease` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['query']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-005 — 'lookup_disease.query' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `lookup_disease` |
| Parameter | `query` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-006 — 'search_diseases' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `search_diseases` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['query']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-007 — initialize accepts protocol version downgrade

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP07 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 75% |

The server accepted initialize with arbitrary protocol versions: ['9999-99-99', '2030-01-01', '1.0', '2024-01-01', '""']. The server also accepted far-future versions, indicating no version validation at all. Servers should reject versions outside their supported range to prevent feature-downgrade attacks.



**Evidence:**
```
Accepted versions: ['9999-99-99', '2030-01-01', '1.0', '2024-01-01', '""']
```


**Remediation:** Validate protocolVersion against a supported range. Return a JSON-RPC error for versions outside that range.

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

### CORVUS-009 — Server accepts path traversal cursor without validation

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



*Generated by [Corvus](https://github.com/CobaltoSec/corvus)*
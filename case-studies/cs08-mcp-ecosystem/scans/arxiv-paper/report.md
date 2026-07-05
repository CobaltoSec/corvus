# Corvus Security Scan Report

**Target:** `uvx arxiv-paper-mcp-server`
**Transport:** stdio
**Date:** 2026-07-05 20:17:31
**Duration:** 81.8s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | arxiv-mcp-server |
| Version | 1.28.1 |
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
| HIGH | 4 |
| MEDIUM | 3 |
| LOW | 2 |
| INFO | 1 |


**Total:** 10 finding(s)

---

## Findings



### CORVUS-001 — Parameter 'target_dir' in 'download_paper' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `download_paper` |
| Parameter | `target_dir` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'target_dir'.

---

### CORVUS-002 — Slow tool response — 'download_paper' took 13.4s

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP10 |
| Tool | `download_paper` |
| Parameter | `—` |
| Confidence | 70% |

Tool 'download_paper' took 13.4 seconds to respond. Slow responses can be used for resource exhaustion in agent pipelines or indicate unbounded computation triggered by benign inputs.



**Evidence:**
```
Response time: 13.36s
```


**Remediation:** Enforce server-side timeouts on all tool executions. Cap at 30s max.

---

### CORVUS-003 — SSRF (timeout) — 'download_paper.paper_id' hung on SSRF payload

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT04 |
| Tool | `download_paper` |
| Parameter | `paper_id` |
| Confidence | 65% |

Call with SSRF payload 'http://169.254.169.254/' timed out after 12.5s, suggesting the server is attempting the network request.


**Payload:**
```
http://169.254.169.254/
```



**Remediation:** Block outbound requests to RFC-1918 and link-local ranges. Use an allowlist for permitted URL schemes and hosts.

---

### CORVUS-004 — SSRF (timeout) — 'download_paper.target_dir' hung on SSRF payload

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT04 |
| Tool | `download_paper` |
| Parameter | `target_dir` |
| Confidence | 65% |

Call with SSRF payload 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' timed out after 12.0s, suggesting the server is attempting the network request.


**Payload:**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```



**Remediation:** Block outbound requests to RFC-1918 and link-local ranges. Use an allowlist for permitted URL schemes and hosts.

---

### CORVUS-005 — initialize accepts protocol version downgrade

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP07 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 75% |

The server accepted initialize with arbitrary protocol versions: ['9999-99-99', '2030-01-01', '1.0', '2024-01-01']. The server also accepted far-future versions, indicating no version validation at all. Servers should reject versions outside their supported range to prevent feature-downgrade attacks.



**Evidence:**
```
Accepted versions: ['9999-99-99', '2030-01-01', '1.0', '2024-01-01']
```


**Remediation:** Validate protocolVersion against a supported range. Return a JSON-RPC error for versions outside that range.

---

### CORVUS-006 — MCP server exposes tools with completable arguments

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

### CORVUS-007 — Protocol crash — JSON-RPC batch array caused server disconnect

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 85% |

Sending a JSON-RPC 2.0 batch (5 requests as an array) caused the server to crash or disconnect. MCP does not define batch semantics; servers must reject arrays gracefully.


**Payload:**
```
[{"jsonrpc":"2.0","id":9000,"method":"tools/list"}, … (5 items)]
```


**Evidence:**
```
Server disconnected after batch. Pre-crash response: none
```


**Remediation:** Validate input type at the JSON-RPC layer: if the parsed value is a list, return -32600 (Invalid Request) immediately without further processing.

---

### CORVUS-008 — Protocol crash — oversized method name caused transport failure

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

### CORVUS-009 — Protocol crash — deeply nested params caused server disconnect

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
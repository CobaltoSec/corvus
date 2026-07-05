# Corvus Security Scan Report

**Target:** `uvx byebye-docs-mcp`
**Transport:** stdio
**Date:** 2026-07-05 20:17:39
**Duration:** 20.4s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | byebye-docs |
| Version | 1.28.1 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 9 |
| Resources | 4 |
| Prompts | 2 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 4 |
| MEDIUM | 4 |
| LOW | 2 |
| INFO | 1 |


**Total:** 11 finding(s)

---

## Findings



### CORVUS-001 — 'list_templates' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `list_templates` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-002 — initialize accepts protocol version downgrade

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

### CORVUS-003 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

9 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---

### CORVUS-004 — Prompt template injection confirmed in 'design-review'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT12 |
| Tool | `design-review` |
| Parameter | `—` |
| Confidence | 88% |

prompts/get for 'design-review' reflected the injection payload verbatim in the returned messages, confirming unsanitized argument reflection.


**Payload:**
```
CORVUS_INJECTION_TEST_{{7*7}}
```


**Evidence:**
```
Payload reflected in messages: {"messages": [{"role": "user", "content": {"type": "text", "text": "\u8a2d\u8a08\u30c9\u30ad\u30e5\u30e1\u30f3\u30c8\u306e\u30ec\u30d3\u30e5\u30fc\u3092\u884c\u3044\u307e\u3059\u3002\n\n\u5bfe\u8c61\u30c9\u30ad\u30e5\u30e1\u30f3\u30c8: CORVUS_INJECTION_TEST_{{7*7}}\n\n\u4ee5\u4e0b\u306e\u89b3\u70b9\
```


**Remediation:** Sanitize prompt arguments before embedding them in message templates.

---

### CORVUS-005 — Prompt template injection confirmed in 'update-architecture'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT12 |
| Tool | `update-architecture` |
| Parameter | `—` |
| Confidence | 88% |

prompts/get for 'update-architecture' reflected the injection payload verbatim in the returned messages, confirming unsanitized argument reflection.


**Payload:**
```
CORVUS_INJECTION_TEST_{{7*7}}
```


**Evidence:**
```
Payload reflected in messages: {"messages": [{"role": "user", "content": {"type": "text", "text": "\u30a2\u30fc\u30ad\u30c6\u30af\u30c1\u30e3\u30c9\u30ad\u30e5\u30e1\u30f3\u30c8\u306e\u66f4\u65b0\u3092\u884c\u3044\u307e\u3059\u3002\n\n\u5909\u66f4\u5185\u5bb9: CORVUS_INJECTION_TEST_{{7*7}}\n\n\u4ee5\u4e0b\u306e\u624b\u9806\u3067\
```


**Remediation:** Sanitize prompt arguments before embedding them in message templates.

---

### CORVUS-006 — Server accepts path traversal cursor without validation

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
Server disconnected after batch. Pre-crash response: {"jsonrpc":"2.0","id":64,"result":{"content":[{"type":"text","text":"[Errno 13] Permission denied: '
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

### CORVUS-011 — Server accepts array request ID — JSON-RPC spec violation

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 65% |

The server returned a successful result to a request with an array as the request ID. JSON-RPC 2.0 requires the id to be a string, number, or null.


**Payload:**
```
{"jsonrpc": "2.0", "id": [1, 2, 3], "method": "tools/list"}
```



**Remediation:** Validate that the request 'id' is a string, number, or null. Return -32600 (Invalid Request) for array or object IDs.

---



*Generated by [Corvus](https://github.com/CobaltoSec/corvus)*
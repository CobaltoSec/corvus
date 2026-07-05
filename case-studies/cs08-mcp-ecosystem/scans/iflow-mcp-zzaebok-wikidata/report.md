# Corvus Security Scan Report

**Target:** `uvx iflow-mcp-zzaebok-wikidata`
**Transport:** stdio
**Date:** 2026-07-05 20:24:29
**Duration:** 66.3s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | Wikidata MCP Server |
| Version | 1.28.1 |
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
| HIGH | 3 |
| MEDIUM | 4 |
| LOW | 4 |
| INFO | 1 |


**Total:** 12 finding(s)

---

## Findings



### CORVUS-001 — High entropy description in 'execute_sparql'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `execute_sparql` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-002 — Shadow Tool — 'execute_sparql' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT03 |
| Tool | `execute_sparql` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'execute_sparql' description contains execution keywords. The tool name is self-documenting (execution verb prefix), so the capability is transparent — but verify the scope is restricted to the intended context.



**Evidence:**
```

Execute a SPARQL query on Wikidata.

You may assume the following prefixes:
PREFIX wd: <http://www.wikidata.org/entity/>
PREFIX wdt: <http://www.wikidata.org/prop/direct/>
PREFIX p: <http://www.wikidata.org/prop/>
PREFIX ps: <http://www.wikidata.org/prop/statement/>

Args:
    sparql_query (str): T
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-003 — 'search_entity' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `search_entity` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-004 — SSRF (timeout) — 'execute_sparql.sparql_query' hung on SSRF payload

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT04 |
| Tool | `execute_sparql` |
| Parameter | `sparql_query` |
| Confidence | 65% |

Call with SSRF payload 'http://127.0.0.1/' timed out after 12.0s, suggesting the server is attempting the network request.


**Payload:**
```
http://127.0.0.1/
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

5 tool(s) have schema properties that may support completion/complete enumeration.




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

### CORVUS-009 — Protocol crash — JSON-RPC batch array caused server disconnect

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

### CORVUS-010 — Protocol crash — oversized method name caused transport failure

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

### CORVUS-011 — Protocol crash — deeply nested params caused server disconnect

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

### CORVUS-012 — Protocol crash — string params caused server disconnect

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
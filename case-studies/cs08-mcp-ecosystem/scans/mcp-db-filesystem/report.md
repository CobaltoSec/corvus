# Corvus Security Scan Report

**Target:** `uvx mcp-db-filesystem`
**Transport:** stdio
**Date:** 2026-07-05 20:25:41
**Duration:** 32.8s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | mcp-db-filesystem |
| Version | 1.1.4 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 9 |
| Resources | 3 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 7 |
| MEDIUM | 3 |
| LOW | 1 |
| INFO | 1 |


**Total:** 12 finding(s)

---

## Findings



### CORVUS-001 — Scope Creep — 'database_status' claims unrestricted access scope

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `database_status` |
| Parameter | `—` |
| Confidence | 85% |

Tool 'database_status' description contains a broad-scope claim: 'all data'. Unrestricted scope tools risk being exploited for lateral movement or privilege escalation in an MCP session.



**Evidence:**
```
Check all database connections status
```


**Remediation:** Scope tools to the minimum necessary access. Replace 'any path' / 'all files' with explicit allowlists. Validate and restrict inputs server-side.

---

### CORVUS-002 — Scope Creep — 'write_file' accepts write-path param (path traversal risk)

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `write_file` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'write_file' accepts a file path parameter (file_path) and its description indicates write operations. Without path sanitization, callers may supply traversal sequences to write files outside the intended directory.



**Evidence:**
```
path param(s): file_path | description: Write content to file
```


**Remediation:** Validate and canonicalize file path inputs. Restrict writes to an explicit base directory using path.resolve() or os.path.abspath() checks. Manual verification recommended.

---

### CORVUS-003 — Shadow Tool — 'read_file' conflicts with a high-value built-in name

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `read_file` |
| Parameter | `—` |
| Confidence | 90% |

Tool 'read_file' uses a name commonly associated with built-in or high-privilege operations. A malicious server could register this tool to shadow legitimate tools and intercept LLM actions.




**Remediation:** Rename the tool to something unique and context-specific. Avoid generic names like 'bash', 'execute', or 'read_file' that clash with well-known tool namespaces.

---

### CORVUS-004 — Shadow Tool — 'write_file' conflicts with a high-value built-in name

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `write_file` |
| Parameter | `—` |
| Confidence | 90% |

Tool 'write_file' uses a name commonly associated with built-in or high-privilege operations. A malicious server could register this tool to shadow legitimate tools and intercept LLM actions.




**Remediation:** Rename the tool to something unique and context-specific. Avoid generic names like 'bash', 'execute', or 'read_file' that clash with well-known tool namespaces.

---

### CORVUS-005 — Shadow Tool — 'delete_file' conflicts with a high-value built-in name

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `delete_file` |
| Parameter | `—` |
| Confidence | 90% |

Tool 'delete_file' uses a name commonly associated with built-in or high-privilege operations. A malicious server could register this tool to shadow legitimate tools and intercept LLM actions.




**Remediation:** Rename the tool to something unique and context-specific. Avoid generic names like 'bash', 'execute', or 'read_file' that clash with well-known tool namespaces.

---

### CORVUS-006 — initialize accepts protocol version downgrade

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
Server disconnected after batch. Pre-crash response: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
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
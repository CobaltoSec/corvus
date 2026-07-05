# Corvus Security Scan Report

**Target:** `uvx zh-file-mcp`
**Transport:** stdio
**Date:** 2026-07-05 20:33:57
**Duration:** 31.5s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | zh-file-mcp |
| Version | 3.4.2 |
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
| HIGH | 4 |
| MEDIUM | 4 |
| LOW | 17 |
| INFO | 1 |


**Total:** 26 finding(s)

---

## Findings



### CORVUS-001 — Parameter 'file_id' in 'download_file' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `download_file` |
| Parameter | `file_id` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'file_id'.

---

### CORVUS-002 — Parameter 'project_id' in 'download_file' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `download_file` |
| Parameter | `project_id` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'project_id'.

---

### CORVUS-003 — Parameter 'download_dir' in 'download_file' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `download_file` |
| Parameter | `download_dir` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'download_dir'.

---

### CORVUS-004 — Parameter 'filename' in 'download_file' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `download_file` |
| Parameter | `filename` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'filename'.

---

### CORVUS-005 — Parameter 'extra' in 'download_file' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `download_file` |
| Parameter | `extra` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'extra'.

---

### CORVUS-006 — Parameter 'project_id' in 'upload_file' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `upload_file` |
| Parameter | `project_id` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'project_id'.

---

### CORVUS-007 — Parameter 'catalog_id' in 'upload_file' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `upload_file` |
| Parameter | `catalog_id` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'catalog_id'.

---

### CORVUS-008 — Parameter 'upload_name' in 'upload_file' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `upload_file` |
| Parameter | `upload_name` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'upload_name'.

---

### CORVUS-009 — Parameter 'extra' in 'upload_file' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `upload_file` |
| Parameter | `extra` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'extra'.

---

### CORVUS-010 — Parameter 'project_id' in 'list_files' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `list_files` |
| Parameter | `project_id` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'project_id'.

---

### CORVUS-011 — Parameter 'parent_id' in 'list_files' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `list_files` |
| Parameter | `parent_id` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'parent_id'.

---

### CORVUS-012 — Parameter 'extra' in 'list_files' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `list_files` |
| Parameter | `extra` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'extra'.

---

### CORVUS-013 — Parameter 'file_id' in 'get_file_info' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `get_file_info` |
| Parameter | `file_id` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'file_id'.

---

### CORVUS-014 — Parameter 'project_id' in 'get_file_info' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `get_file_info` |
| Parameter | `project_id` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'project_id'.

---

### CORVUS-015 — Parameter 'extra' in 'get_file_info' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `get_file_info` |
| Parameter | `extra` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'extra'.

---

### CORVUS-016 — Injection reflected — 'download_file.system'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `download_file` |
| Parameter | `system` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
{"status":"error","error":"unknown system: <script>alert(1)</script>","type":"ValueError"}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-017 — initialize accepts protocol version downgrade

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

### CORVUS-018 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

4 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---

### CORVUS-019 — Server allows external log level escalation to DEBUG

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT11 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 85% |

The MCP server accepted an unauthenticated logging/setLevel request with level='debug'. This may expose tokens, internal paths, and sensitive state in log streams accessible to the operator.



**Evidence:**
```
logging/setLevel with level='debug' and level='emergency' both returned success
```


**Remediation:** Restrict logging/setLevel to admin contexts or disable it entirely.

---

### CORVUS-020 — Server accepts path traversal cursor without validation

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

### CORVUS-021 — Protocol crash — JSON-RPC batch array caused server disconnect

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

### CORVUS-022 — Protocol crash — oversized method name caused transport failure

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

### CORVUS-023 — Protocol crash — deeply nested params caused server disconnect

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

### CORVUS-024 — Protocol crash — string params caused server disconnect

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

### CORVUS-025 — Server accepts requests without jsonrpc field

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 70% |

The server returned a successful result to a request missing the required 'jsonrpc' field. Per JSON-RPC 2.0, this field is mandatory and must equal '2.0'.


**Payload:**
```
{"id": 9600, "method": "tools/list", "params": {}}
```



**Remediation:** Validate that the 'jsonrpc' field is present and equals '2.0' before processing. Return -32600 (Invalid Request) for non-conformant messages.

---

### CORVUS-026 — Server accepts array request ID — JSON-RPC spec violation

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
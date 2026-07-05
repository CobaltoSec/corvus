# Corvus Security Scan Report

**Target:** `uvx mcp-database`
**Transport:** stdio
**Date:** 2026-07-05 20:25:19
**Duration:** 19.7s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | Database Server |
| Version | 1.28.1 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 13 |
| Resources | 1 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 4 |
| MEDIUM | 6 |
| LOW | 9 |
| INFO | 4 |


**Total:** 23 finding(s)

---

## Findings



### CORVUS-001 — Scope Creep — 'get_schema' is named read-only but description implies write access

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP02 |
| Tool | `get_schema` |
| Parameter | `—` |
| Confidence | 70% |

Tool 'get_schema' has a read-only prefix but its description mentions write operations ('CREATE'), creating a scope mismatch that callers and LLMs may be unable to detect.



**Evidence:**
```
Get the full database schema (CREATE TABLE statements for all tables).

Args:
    database: Name of the database within the connection (optional).
    connection_name: Name of the database connection (default: "default").

```


**Remediation:** Separate read and write operations into distinct tools. Ensure tool names accurately reflect their full capabilities.

---

### CORVUS-002 — Parameter 'database' in 'list_tables' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `list_tables` |
| Parameter | `database` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'database'.

---

### CORVUS-003 — Parameter 'database' in 'get_table_info' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `get_table_info` |
| Parameter | `database` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'database'.

---

### CORVUS-004 — Parameter 'database' in 'get_schema' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `get_schema` |
| Parameter | `database` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'database'.

---

### CORVUS-005 — Parameter 'database' in 'query' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `query` |
| Parameter | `database` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'database'.

---

### CORVUS-006 — Parameter 'database' in 'execute' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `execute` |
| Parameter | `database` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'database'.

---

### CORVUS-007 — Parameter 'database' in 'sample_rows' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `sample_rows` |
| Parameter | `database` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'database'.

---

### CORVUS-008 — Parameter 'database' in 'search_tables' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `search_tables` |
| Parameter | `database` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'database'.

---

### CORVUS-009 — 'check_health' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `check_health` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-010 — 'generate_er_diagram' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `generate_er_diagram` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-011 — 'diagnose_connection' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `diagnose_connection` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-012 — Shadow Tool — 'query' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `query` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'query' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
Execute a read-only SQL query (SELECT, SHOW, DESCRIBE, EXPLAIN) and return results.

Args:
    sql: SQL query to execute.
    database: Name of the database within the connection (optional).
    max_rows: Maximum number of rows to return (default: 100).
    connection_name: Name of the database conn
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-013 — Shadow Tool — 'execute' (scope-restricted)

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT03 |
| Tool | `execute` |
| Parameter | `—` |
| Confidence | 70% |

Tool 'execute' uses a name commonly associated with built-in or high-privilege operations. A malicious server could register this tool to shadow legitimate tools and intercept LLM actions.




**Remediation:** Rename the tool to something unique and context-specific. Avoid generic names like 'bash', 'execute', or 'read_file' that clash with well-known tool namespaces.

---

### CORVUS-014 — Shadow Tool — 'execute' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `execute` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'execute' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
Execute a write SQL statement (INSERT, UPDATE, DELETE). Only works if writes are enabled.

Args:
    sql: SQL statement to execute.
    database: Name of the database within the connection (optional).
    connection_name: Name of the database connection (default: "default").

```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-015 — 'list_tables' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `list_tables` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-016 — initialize accepts protocol version downgrade

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

### CORVUS-017 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

12 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---

### CORVUS-018 — Server accepts path traversal cursor without validation

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

### CORVUS-019 — Protocol crash — JSON-RPC batch array caused server disconnect

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
Server disconnected after batch. Pre-crash response: {"jsonrpc":"2.0","id":62,"result":{"content":[{"type":"text","text":"Error: Write operations are dis
```


**Remediation:** Validate input type at the JSON-RPC layer: if the parsed value is a list, return -32600 (Invalid Request) immediately without further processing.

---

### CORVUS-020 — Protocol crash — oversized method name caused transport failure

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

### CORVUS-021 — Protocol crash — deeply nested params caused server disconnect

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

### CORVUS-023 — Server accepts array request ID — JSON-RPC spec violation

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
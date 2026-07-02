# Corvus Security Scan Report

**Target:** `npx -y @henkey/postgres-mcp-server`
**Transport:** stdio
**Date:** 2026-07-02 14:47:45
**Duration:** 70.1s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | postgresql-mcp-server |
| Version | 1.0.7 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 18 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 4 |
| LOW | 1 |
| INFO | 2 |


**Total:** 9 finding(s)

---

## Findings



### CORVUS-001 — Scope Creep — 'pg_manage_users' inputSchema requests credential fields

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `pg_manage_users` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'pg_manage_users' inputSchema declares field(s) associated with credentials or secrets: password. This may indicate the tool harvests authentication material from the LLM caller.



**Evidence:**
```
inputSchema properties: password
```


**Remediation:** Do not accept raw credentials as tool input parameters. Use secure credential stores and reference by identifier, not value.

---

### CORVUS-002 — 'pg_analyze_database' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `pg_analyze_database` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-003 — 'pg_monitor_database' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `pg_monitor_database` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-004 — Shadow Tool — 'pg_execute_query' (DB tool) description reveals execution intent

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT03 |
| Tool | `pg_execute_query` |
| Parameter | `—` |
| Confidence | 60% |

Tool 'pg_execute_query' description contains execution keywords. DB-prefixed tools legitimately execute queries, but verify the scope is restricted to the intended database context.



**Evidence:**
```
Execute SELECT queries and data retrieval operations - operation="select/count/exists" with query and optional parameters. Examples: operation="select", query="SELECT * FROM users WHERE created_at > $1", parameters=["2024-01-01"]
```


**Remediation:** Declare the allowed SQL operation types in the schema and reject statements outside the declared scope (e.g. no DDL if tool is DQL only).

---

### CORVUS-005 — Shadow Tool — 'pg_execute_mutation' (DB tool) description reveals execution intent

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT03 |
| Tool | `pg_execute_mutation` |
| Parameter | `—` |
| Confidence | 60% |

Tool 'pg_execute_mutation' description contains execution keywords. DB-prefixed tools legitimately execute queries, but verify the scope is restricted to the intended database context.



**Evidence:**
```
Execute data modification operations (INSERT/UPDATE/DELETE/UPSERT) - operation="insert/update/delete/upsert" with table and data. Examples: operation="insert", table="users", data={"name":"John","email":"john@example.com"}
```


**Remediation:** Declare the allowed SQL operation types in the schema and reject statements outside the declared scope (e.g. no DDL if tool is DQL only).

---

### CORVUS-006 — Shadow Tool — 'pg_execute_sql' (DB tool) description reveals execution intent

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT03 |
| Tool | `pg_execute_sql` |
| Parameter | `—` |
| Confidence | 60% |

Tool 'pg_execute_sql' description contains execution keywords. DB-prefixed tools legitimately execute queries, but verify the scope is restricted to the intended database context.



**Evidence:**
```
Execute arbitrary SQL statements - sql="ANY_VALID_SQL" with optional parameters and transaction support. Examples: sql="CREATE INDEX ...", sql="WITH complex_cte AS (...) SELECT ...", transactional=true
```


**Remediation:** Declare the allowed SQL operation types in the schema and reject statements outside the declared scope (e.g. no DDL if tool is DQL only).

---

### CORVUS-007 — Protocol crash — oversized method name caused transport failure

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

### CORVUS-008 — Protocol crash — deeply nested params caused server disconnect

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

### CORVUS-009 — Protocol crash — string params caused server disconnect

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
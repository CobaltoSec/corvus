# Corvus Security Scan Report

**Target:** `npx -y @berthojoris/mcp-mysql-server mysql://root:root@localhost:3306/test`
**Transport:** stdio
**Date:** 2026-07-02 14:55:01
**Duration:** 66.7s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | mysql-mcp-server |
| Version | 1.43.0 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 88 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 8 |
| MEDIUM | 17 |
| LOW | 11 |
| INFO | 3 |


**Total:** 39 finding(s)

---

## Findings



### CORVUS-001 — Scope Creep — 'list_databases' claims unrestricted access scope

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `list_databases` |
| Parameter | `—` |
| Confidence | 85% |

Tool 'list_databases' description contains a broad-scope claim: 'all data'. Unrestricted scope tools risk being exploited for lateral movement or privilege escalation in an MCP session.



**Evidence:**
```
Lists all databases available on the MySQL server. Use this to discover what databases exist before querying them.
```


**Remediation:** Scope tools to the minimum necessary access. Replace 'any path' / 'all files' with explicit allowlists. Validate and restrict inputs server-side.

---

### CORVUS-002 — High entropy description in 'run_select_query'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `run_select_query` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-003 — High entropy description in 'execute_ddl'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `execute_ddl` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-004 — High entropy description in 'cursor_execute_request'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `cursor_execute_request` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-005 — Parameter 'rows_per_table' in 'plan_seed_data' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `plan_seed_data` |
| Parameter | `rows_per_table` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'rows_per_table'.

---

### CORVUS-006 — 'infer_seed_rules' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `infer_seed_rules` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-007 — Parameter 'rows_per_table' in 'seed_from_template' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `seed_from_template` |
| Parameter | `rows_per_table` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'rows_per_table'.

---

### CORVUS-008 — 'begin_transaction' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `begin_transaction` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-009 — 'flush_table' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `flush_table` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-010 — Shadow Tool — 'execute_seed_plan' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `execute_seed_plan` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'execute_seed_plan' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
🌱 RELATIONAL SEEDER: Executes a confirmed seed plan with dry-run enabled by default, production-name guard, transaction rollback on errors, and foreign-key ID resolution.
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-011 — Shadow Tool — 'run_select_query' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `run_select_query` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'run_select_query' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
⚡ PRIMARY TOOL FOR SELECT QUERIES. Executes read-only SELECT statements with parameterization, optimizer hints, query caching, and dry-run mode. Supports complex queries with JOINs, subqueries, and aggregations. ⚠️ ONLY for SELECT - use execute_write_query for INSERT/UPDATE, use execute_ddl for CREA
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-012 — Shadow Tool — 'execute_write_query' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `execute_write_query` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'execute_write_query' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
⚡ PRIMARY TOOL FOR INSERT/UPDATE QUERIES. Executes data modification statements with parameterization support. Returns affected row count and execution details. DELETE SQL requires the separate "delete" permission in addition to "execute". ⚠️ NOT for SELECT (use run_select_query), NOT for DDL (use e
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-013 — Shadow Tool — 'execute_ddl' (DB tool) description reveals execution intent

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT03 |
| Tool | `execute_ddl` |
| Parameter | `—` |
| Confidence | 60% |

Tool 'execute_ddl' description contains execution keywords. DB-prefixed tools legitimately execute queries, but verify the scope is restricted to the intended database context.



**Evidence:**
```
⚡ PRIMARY TOOL FOR DDL STATEMENTS. Executes schema modification queries: CREATE, ALTER, DROP, TRUNCATE, RENAME. Use for complex DDL that structured tools don't cover. ⚠️ NOT for SELECT (use run_select_query), NOT for INSERT/UPDATE/DELETE (use execute_write_query). Requires "ddl" permission.
```


**Remediation:** Declare the allowed SQL operation types in the schema and reject statements outside the declared scope (e.g. no DDL if tool is DQL only).

---

### CORVUS-014 — Shadow Tool — 'execute_in_transaction' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `execute_in_transaction` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'execute_in_transaction' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
Executes a SQL query within an existing transaction context. The query becomes part of the transaction and will be committed or rolled back with it. Use after begin_transaction.
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-015 — Shadow Tool — 'execute_stored_procedure' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `execute_stored_procedure` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'execute_stored_procedure' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
Executes a stored procedure with optional parameters.
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-016 — Shadow Tool — 'export_query_to_csv' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `export_query_to_csv` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'export_query_to_csv' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
📄 Executes a SELECT query and exports results to CSV format. Supports complex queries with JOINs and aggregations. For sensitive data, consider using safe_export_table or adding manual data masking.
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-017 — Tool Chaining — 'begin_transaction' directs LLM to call commit_transaction

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT06 |
| Tool | `begin_transaction` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'begin_transaction' description references tool(s) 'commit_transaction', 'rollback_transaction' from the same server using imperative language. This pattern can force an LLM into an unintended call chain or manufacture urgency to invoke a privileged tool.



**Evidence:**
```
🔄 Starts a new database transaction and returns a transaction ID. Use with commit_transaction or rollback_transaction to group multiple operations atomically. Essential for data consistency when multiple changes must succeed or fail together.
```


**Remediation:** Tool descriptions should describe what the tool does — not instruct the LLM on what other tools to call. Remove cross-tool directives and let the caller decide the execution order.

---

### CORVUS-018 — Injection reflected — 'repair_query.error_message'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `repair_query` |
| Parameter | `error_message` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: sql).


**Payload:**
```
' OR '1'='1
```


**Evidence:**
```
{
  "status": "success",
  "suggestions": [
    "Check SQL syntax matching your MySQL version.",
    "Verify table and column names using 'list_tables' or 'read_table_schema'.",
    "Ensure string literals are quoted correctly."
  ],
  "fixed_query": "test",
  "analysis": {
    "issue": "Syntax/Exec
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-019 — Injection reflected — 'analyze_query.query'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `analyze_query` |
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
  "originalQuery": "' OR '1'='1",
  "queryType": "OTHER",
  "tables": [],
  "hasJoins": false,
  "hasSubqueries": false,
  "hasGroupBy": false,
  "hasOrderBy": false,
  "hasLimit": false,
  "estimatedComplexity": "LOW",
  "suggestions": []
}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-020 — Injection reflected — 'get_optimization_hints.goal'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `get_optimization_hints` |
| Parameter | `goal` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
{
  "goal": "<script>alert(1)</script>",
  "hints": {}
}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-021 — 'analyze_query' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `analyze_query` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-022 — 'get_optimization_hints' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `get_optimization_hints` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['goal']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-023 — 'get_optimization_hints.goal' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_optimization_hints` |
| Parameter | `goal` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-024 — 'get_optimization_hints' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_optimization_hints` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-025 — Hidden param accepted — 'list_tables' responds differently to _debug

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `list_tables` |
| Parameter | `—` |
| Confidence | 55% |

Parameter '_debug' caused a response size or format change. The server may be accepting undeclared parameters. Probe response significantly larger: 45 → 208 chars


**Payload:**
```
{"_debug": true}
```


**Evidence:**
```
Diff: Probe response significantly larger: 45 → 208 chars
```


**Remediation:** Set additionalProperties: false in the tool schema and reject unknown parameters. Validate all inputs against a strict allowlist.

---

### CORVUS-026 — Hidden param accepted — 'read_table_schema' responds differently to _debug

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `read_table_schema` |
| Parameter | `—` |
| Confidence | 55% |

Parameter '_debug' caused a response size or format change. The server may be accepting undeclared parameters. Probe response significantly larger: 45 → 208 chars


**Payload:**
```
{"_debug": true}
```


**Evidence:**
```
Diff: Probe response significantly larger: 45 → 208 chars
```


**Remediation:** Set additionalProperties: false in the tool schema and reject unknown parameters. Validate all inputs against a strict allowlist.

---

### CORVUS-027 — Hidden param accepted — 'create_record' responds differently to _debug

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `create_record` |
| Parameter | `—` |
| Confidence | 55% |

Parameter '_debug' caused a response size or format change. The server may be accepting undeclared parameters. Probe response significantly larger: 62 → 123 chars


**Payload:**
```
{"_debug": true}
```


**Evidence:**
```
Diff: Probe response significantly larger: 62 → 123 chars
```


**Remediation:** Set additionalProperties: false in the tool schema and reject unknown parameters. Validate all inputs against a strict allowlist.

---

### CORVUS-028 — Hidden param accepted — 'update_record' responds differently to _debug

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `update_record` |
| Parameter | `—` |
| Confidence | 55% |

Parameter '_debug' caused a response size or format change. The server may be accepting undeclared parameters. Probe response significantly larger: 109 → 170 chars


**Payload:**
```
{"_debug": true}
```


**Evidence:**
```
Diff: Probe response significantly larger: 109 → 170 chars
```


**Remediation:** Set additionalProperties: false in the tool schema and reject unknown parameters. Validate all inputs against a strict allowlist.

---

### CORVUS-029 — Hidden param accepted — 'delete_record' responds differently to _debug

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `delete_record` |
| Parameter | `—` |
| Confidence | 55% |

Parameter '_debug' caused a response size or format change. The server may be accepting undeclared parameters. Probe response significantly larger: 63 → 124 chars


**Payload:**
```
{"_debug": true}
```


**Evidence:**
```
Diff: Probe response significantly larger: 63 → 124 chars
```


**Remediation:** Set additionalProperties: false in the tool schema and reject unknown parameters. Validate all inputs against a strict allowlist.

---

### CORVUS-030 — Hidden param accepted — 'bulk_insert' responds differently to _debug

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `bulk_insert` |
| Parameter | `—` |
| Confidence | 55% |

Parameter '_debug' caused a response size or format change. The server may be accepting undeclared parameters. Probe response significantly larger: 57 → 118 chars


**Payload:**
```
{"_debug": true}
```


**Evidence:**
```
Diff: Probe response significantly larger: 57 → 118 chars
```


**Remediation:** Set additionalProperties: false in the tool schema and reject unknown parameters. Validate all inputs against a strict allowlist.

---

### CORVUS-031 — Hidden param accepted — 'list_stored_procedures' responds differently to _debug

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `list_stored_procedures` |
| Parameter | `—` |
| Confidence | 55% |

Parameter '_debug' caused a response size or format change. The server may be accepting undeclared parameters. Probe response significantly larger: 45 → 208 chars


**Payload:**
```
{"_debug": true}
```


**Evidence:**
```
Diff: Probe response significantly larger: 45 → 208 chars
```


**Remediation:** Set additionalProperties: false in the tool schema and reject unknown parameters. Validate all inputs against a strict allowlist.

---

### CORVUS-032 — Hidden param accepted — 'get_stored_procedure_info' responds differently to _debug

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `get_stored_procedure_info` |
| Parameter | `—` |
| Confidence | 55% |

Parameter '_debug' caused a response size or format change. The server may be accepting undeclared parameters. Probe response significantly larger: 45 → 208 chars


**Payload:**
```
{"_debug": true}
```


**Evidence:**
```
Diff: Probe response significantly larger: 45 → 208 chars
```


**Remediation:** Set additionalProperties: false in the tool schema and reject unknown parameters. Validate all inputs against a strict allowlist.

---

### CORVUS-033 — Hidden param accepted — 'execute_stored_procedure' responds differently to _debug

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `execute_stored_procedure` |
| Parameter | `—` |
| Confidence | 55% |

Parameter '_debug' caused a response size or format change. The server may be accepting undeclared parameters. Probe response significantly larger: 87 → 208 chars


**Payload:**
```
{"_debug": true}
```


**Evidence:**
```
Diff: Probe response significantly larger: 87 → 208 chars
```


**Remediation:** Set additionalProperties: false in the tool schema and reject unknown parameters. Validate all inputs against a strict allowlist.

---

### CORVUS-034 — Hidden param accepted — 'create_stored_procedure' responds differently to _debug

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `create_stored_procedure` |
| Parameter | `—` |
| Confidence | 55% |

Parameter '_debug' caused a response size or format change. The server may be accepting undeclared parameters. Probe response significantly larger: 45 → 208 chars


**Payload:**
```
{"_debug": true}
```


**Evidence:**
```
Diff: Probe response significantly larger: 45 → 208 chars
```


**Remediation:** Set additionalProperties: false in the tool schema and reject unknown parameters. Validate all inputs against a strict allowlist.

---

### CORVUS-035 — Hidden param accepted — 'drop_stored_procedure' responds differently to _debug

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `drop_stored_procedure` |
| Parameter | `—` |
| Confidence | 55% |

Parameter '_debug' caused a response size or format change. The server may be accepting undeclared parameters. Probe response significantly larger: 45 → 208 chars


**Payload:**
```
{"_debug": true}
```


**Evidence:**
```
Diff: Probe response significantly larger: 45 → 208 chars
```


**Remediation:** Set additionalProperties: false in the tool schema and reject unknown parameters. Validate all inputs against a strict allowlist.

---

### CORVUS-036 — Hidden param accepted — 'show_create_procedure' responds differently to _debug

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `show_create_procedure` |
| Parameter | `—` |
| Confidence | 55% |

Parameter '_debug' caused a response size or format change. The server may be accepting undeclared parameters. Probe response significantly larger: 45 → 208 chars


**Payload:**
```
{"_debug": true}
```


**Evidence:**
```
Diff: Probe response significantly larger: 45 → 208 chars
```


**Remediation:** Set additionalProperties: false in the tool schema and reject unknown parameters. Validate all inputs against a strict allowlist.

---

### CORVUS-037 — initialize accepts protocol version downgrade

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

### CORVUS-038 — Null request ID accepted — JSON-RPC spec violation

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

### CORVUS-039 — Protocol crash — string params caused server disconnect

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
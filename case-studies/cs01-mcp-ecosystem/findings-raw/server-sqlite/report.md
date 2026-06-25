# Corvus Security Scan Report

**Target:** `uvx mcp-server-sqlite --db-path C:\Temp\test.db`
**Transport:** stdio
**Date:** 2026-06-25 09:39:31
**Duration:** 7.5s
**Modules:** scope-audit, supply-chain, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull

---

## Server Info

| Field | Value |
|-------|-------|
| Name | sqlite |
| Version | 0.1.0 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 6 |
| Resources | 1 |
| Prompts | 1 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 2 |
| LOW | 8 |
| INFO | 0 |


**Total:** 12 finding(s)

---

## Findings



### CORVUS-001 — Injection reflected — 'write_query.query'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `write_query` |
| Parameter | `query` |

Payload was reflected verbatim in the response without sanitization (field classification: command).


**Payload:**
```
`id`
```


**Evidence:**
```
Database error: near "`id`": syntax error
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-002 — Injection reflected — 'describe_table.table_name'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `describe_table` |
| Parameter | `table_name` |

Payload was reflected verbatim in the response without sanitization (field classification: generic_string).


**Payload:**
```
null
```


**Evidence:**
```
Database error: near "null": syntax error
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-003 — 'read_query.query' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `read_query` |
| Parameter | `query` |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-004 — 'read_query' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `read_query` |
| Parameter | `—` |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-005 — 'write_query' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `write_query` |
| Parameter | `—` |

Tool succeeded with empty arguments despite required: ['query']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-006 — 'write_query.query' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `write_query` |
| Parameter | `query` |

Expected type 'string', sent int value '12345' — no error returned.


**Payload:**
```
12345
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-007 — 'write_query' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `write_query` |
| Parameter | `—` |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-008 — 'create_table.query' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `create_table` |
| Parameter | `query` |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-009 — 'create_table' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `create_table` |
| Parameter | `—` |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-010 — 'describe_table' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `describe_table` |
| Parameter | `—` |

Tool succeeded with empty arguments despite required: ['table_name']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-011 — 'describe_table.table_name' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `describe_table` |
| Parameter | `table_name` |

Expected type 'string', sent bool value 'True' — no error returned.


**Payload:**
```
True
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-012 — 'append_insight.insight' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `append_insight` |
| Parameter | `insight` |

Expected type 'string', sent int value '12345' — no error returned.


**Payload:**
```
12345
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---



*Generated by [Corvus](https://github.com/CobaltoSec/corvus)*
# Corvus Security Scan Report

**Target:** `uvx mcp-msaccess-database`
**Transport:** stdio
**Date:** 2026-07-05 20:26:59
**Duration:** 26.3s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | access-mcp |
| Version | 1.28.1 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 67 |
| Resources | 0 |
| Prompts | 1 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 12 |
| MEDIUM | 4 |
| LOW | 5 |
| INFO | 2 |


**Total:** 23 finding(s)

---

## Findings



### CORVUS-001 — Scope Creep — 'access_export_structure' accepts write-path param (path traversal risk)

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `access_export_structure` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'access_export_structure' accepts a file path parameter (output_path) and its description indicates write operations. Without path sanitization, callers may supply traversal sequences to write files outside the intended directory.



**Evidence:**
```
path param(s): output_path | description: Generates Markdown with database structure: modules with signatures, forms, reports, queries, macros. Writes to disk and returns the content.
```


**Remediation:** Validate and canonicalize file path inputs. Restrict writes to an explicit base directory using path.resolve() or os.path.abspath() checks. Manual verification recommended.

---

### CORVUS-002 — Scope Creep — 'access_export_text' accepts write-path param (path traversal risk)

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `access_export_text` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'access_export_text' accepts a file path parameter (output_path) and its description indicates write operations. Without path sanitization, callers may supply traversal sequences to write files outside the intended directory.



**Evidence:**
```
path param(s): output_path | description: Exports form/report/module as text (SaveAsText). Does NOT open in Design view — does not recalculate positions. File is UTF-16 LE.
```


**Remediation:** Validate and canonicalize file path inputs. Restrict writes to an explicit base directory using path.resolve() or os.path.abspath() checks. Manual verification recommended.

---

### CORVUS-003 — Scope Creep — 'access_output_report' accepts write-path param (path traversal risk)

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `access_output_report` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'access_output_report' accepts a file path parameter (output_path) and its description indicates write operations. Without path sanitization, callers may supply traversal sequences to write files outside the intended directory.



**Evidence:**
```
path param(s): output_path | description: Exports a report to PDF, XLSX, RTF or TXT. output_path auto-generated if omitted. Refuses to overwrite an existing file unless overwrite=true.
```


**Remediation:** Validate and canonicalize file path inputs. Restrict writes to an explicit base directory using path.resolve() or os.path.abspath() checks. Manual verification recommended.

---

### CORVUS-004 — Scope Creep — 'access_transfer_data' accepts write-path param (path traversal risk)

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `access_transfer_data` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'access_transfer_data' accepts a file path parameter (file_path) and its description indicates write operations. Without path sanitization, callers may supply traversal sequences to write files outside the intended directory.



**Evidence:**
```
path param(s): file_path | description: Import/export data between Access and Excel/CSV. file_type: xlsx or csv. range only for Excel, spec_name only for CSV.
```


**Remediation:** Validate and canonicalize file path inputs. Restrict writes to an explicit base directory using path.resolve() or os.path.abspath() checks. Manual verification recommended.

---

### CORVUS-005 — Parameter 'value' in 'access_set_db_property' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `access_set_db_property` |
| Parameter | `value` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'value'.

---

### CORVUS-006 — Parameter 'value' in 'access_set_field_property' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `access_set_field_property` |
| Parameter | `value` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'value'.

---

### CORVUS-007 — Parameter 'default' in 'access_alter_table' has no type constraint

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT02 |
| Tool | `access_alter_table` |
| Parameter | `default` |
| Confidence | 80% |

Untyped parameters accept any value, making input validation harder to enforce.




**Remediation:** Add an explicit type to parameter 'default'.

---

### CORVUS-008 — 'access_tips' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `access_tips` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-009 — Shadow Tool — 'access_execute_sql' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `access_execute_sql` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'access_execute_sql' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
Executes SQL via DAO. SELECT returns JSON rows (default limit: 500). INSERT/UPDATE return affected_rows. DELETE/DROP/ALTER require confirm_destructive=true.
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-010 — Shadow Tool — 'access_vbe_replace_lines' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `access_vbe_replace_lines` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'access_vbe_replace_lines' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
Replaces lines in a VBA module via VBE. count=0: insertion. new_code='': deletion. Validates bounds automatically. Pass new code as new_code (a string) OR new_lines (a list of strings, joined with newlines — '' entries become blank lines). Batch mode: pass 'operations' (list of {start_line, count, n
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-011 — Shadow Tool — 'access_run_macro' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `access_run_macro` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'access_run_macro' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
Executes an Access macro by name.
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-012 — Shadow Tool — 'access_run_vba' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `access_run_vba` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'access_run_vba' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
Executes a VBA Sub/Function. Supports 3 syntaxes: 'Module.MySub' (standard module via Application.Run), 'MySub' (same), 'Forms.FormName.Method' (form module via COM — form must be open). Returns result if Function. With timeout, automatically dismisses MsgBox/InputBox if exceeded.
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-013 — Shadow Tool — 'access_execute_batch' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `access_execute_batch` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'access_execute_batch' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
Executes multiple SQL statements in a single call. Each statement can be SELECT (returns rows, default limit 100 — adjustable via 'limit') or INSERT/UPDATE/DELETE (returns affected_rows). stop_on_error=true stops at first error. DELETE/DROP/TRUNCATE/ALTER require confirm_destructive=true.
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-014 — initialize accepts protocol version downgrade

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

### CORVUS-015 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

66 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---

### CORVUS-016 — Prompt template injection confirmed in 'access-workflow'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT12 |
| Tool | `access-workflow` |
| Parameter | `—` |
| Confidence | 88% |

prompts/get for 'access-workflow' reflected the injection payload verbatim in the returned messages, confirming unsanitized argument reflection.


**Payload:**
```
CORVUS_INJECTION_TEST_{{7*7}}
```


**Evidence:**
```
Payload reflected in messages: {"description": "Required workflow for working with Access databases", "messages": [{"role": "user", "content": {"type": "text", "text": "\nI'm working with a Microsoft Access database: CORVUS_INJECTION_TEST_{{7*7}}\n\nREQUIRED RULES for the agent:\n1. Any operation on .accdb or .mdb files MUST be d
```


**Remediation:** Sanitize prompt arguments before embedding them in message templates.

---

### CORVUS-017 — Server accepts path traversal cursor without validation

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

### CORVUS-018 — Protocol crash — JSON-RPC batch array caused server disconnect

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
Server disconnected after batch. Pre-crash response: {"jsonrpc":"2.0","id":44,"result":{"content":[{"type":"text","text":"Input validation error: 'test' 
```


**Remediation:** Validate input type at the JSON-RPC layer: if the parsed value is a list, return -32600 (Invalid Request) immediately without further processing.

---

### CORVUS-019 — Protocol crash — oversized method name caused transport failure

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

### CORVUS-020 — Protocol crash — deeply nested params caused server disconnect

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

### CORVUS-021 — Protocol crash — string params caused server disconnect

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

### CORVUS-022 — Server accepts requests without jsonrpc field

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
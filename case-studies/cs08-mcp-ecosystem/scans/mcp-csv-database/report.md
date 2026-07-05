# Corvus Security Scan Report

**Target:** `uvx mcp-csv-database`
**Transport:** stdio
**Date:** 2026-07-05 20:25:23
**Duration:** 34.3s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | CSV Database Server |
| Version | 1.28.1 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 14 |
| Resources | 0 |
| Prompts | 1 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 5 |
| MEDIUM | 5 |
| LOW | 2 |
| INFO | 1 |


**Total:** 13 finding(s)

---

## Findings



### CORVUS-001 — Scope Creep — 'export_table_to_csv' accepts write-path param (path traversal risk)

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `export_table_to_csv` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'export_table_to_csv' accepts a file path parameter (output_path) and its description indicates write operations. Without path sanitization, callers may supply traversal sequences to write files outside the intended directory.



**Evidence:**
```
path param(s): output_path | description: 
Export a table to a CSV file.

Args:
    table_name: Name of the table to export
    output_path: Path for the output CSV file
    include_header: Whether to include column headers

Returns:
    Stat
```


**Remediation:** Validate and canonicalize file path inputs. Restrict writes to an explicit base directory using path.resolve() or os.path.abspath() checks. Manual verification recommended.

---

### CORVUS-002 — Shadow Tool — 'execute_sql_query' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT03 |
| Tool | `execute_sql_query` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'execute_sql_query' description contains execution keywords. The tool name is self-documenting (execution verb prefix), so the capability is transparent — but verify the scope is restricted to the intended context.



**Evidence:**
```

Execute any SQL query on the loaded database.

Args:
    query: Any SQL query to execute (SELECT, INSERT, UPDATE, DELETE, CREATE, etc.)
    limit: Maximum number of rows to return for SELECT queries (default: 100)

Returns:
    Query results formatted as JSON

```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-003 — Injection reflected — 'load_csv_folder.folder_path'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `load_csv_folder` |
| Parameter | `folder_path` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
{"function_results_id": "34cad606", "status": "error", "message": "Folder '<script>alert(1)</script>' does not exist."}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-004 — initialize accepts protocol version downgrade

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

### CORVUS-005 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

11 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---

### CORVUS-006 — Prompt template injection confirmed in 'analyze_data_prompt'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT12 |
| Tool | `analyze_data_prompt` |
| Parameter | `—` |
| Confidence | 88% |

prompts/get for 'analyze_data_prompt' reflected the injection payload verbatim in the returned messages, confirming unsanitized argument reflection.


**Payload:**
```
CORVUS_INJECTION_TEST_{{7*7}}
```


**Evidence:**
```
Payload reflected in messages: {"description": "\nGenerate a prompt for analyzing data in a specific table.\n\nArgs:\n    table_name: Name of the table to analyze\n    analysis_type: Type of analysis (summary, trends, insights, etc.)\n", "messages": [{"role": "user", "content": {"type": "text", "text": "Table 'CORVUS_INJECTION_TE
```


**Remediation:** Sanitize prompt arguments before embedding them in message templates.

---

### CORVUS-007 — Server accepts path traversal cursor without validation

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

### CORVUS-008 — Protocol crash — JSON-RPC batch array caused server disconnect

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

### CORVUS-009 — Protocol crash — oversized method name caused transport failure

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

### CORVUS-010 — Protocol crash — deeply nested params caused server disconnect

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

### CORVUS-011 — Protocol crash — string params caused server disconnect

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

### CORVUS-012 — Server accepts requests without jsonrpc field

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

### CORVUS-013 — Server accepts array request ID — JSON-RPC spec violation

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
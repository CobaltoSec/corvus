# Corvus Security Scan Report

**Target:** `npx -y @remnux/mcp-server`
**Transport:** stdio
**Date:** 2026-07-02 14:51:34
**Duration:** 93.0s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | remnux-mcp-server |
| Version | 0.1.58 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 18 |
| Resources | 148 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 6 |
| MEDIUM | 9 |
| LOW | 1 |
| INFO | 0 |


**Total:** 17 finding(s)

---

## Findings



### CORVUS-001 — Scope Creep — 'extract_archive' inputSchema requests credential fields

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `extract_archive` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'extract_archive' inputSchema declares field(s) associated with credentials or secrets: password. This may indicate the tool harvests authentication material from the LLM caller.



**Evidence:**
```
inputSchema properties: password
```


**Remediation:** Do not accept raw credentials as tool input parameters. Use secure credential stores and reference by identifier, not value.

---

### CORVUS-002 — Scope Creep — 'download_file' accepts write-path param (path traversal risk)

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `download_file` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'download_file' accepts a file path parameter (file_path, output_path) and its description indicates write operations. Without path sanitization, callers may supply traversal sequences to write files outside the intended directory.



**Evidence:**
```
path param(s): file_path, output_path | description: Download a file from the output directory (returns base64-encoded content). Use this to retrieve analysis results. Files are wrapped in a password-protected archive by default to prevent AV/EDR trigge
```


**Remediation:** Validate and canonicalize file path inputs. Restrict writes to an explicit base directory using path.resolve() or os.path.abspath() checks. Manual verification recommended.

---

### CORVUS-003 — Supply Chain — 'uuid' has moderate vulnerability (no CVE assigned)

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP04 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 65% |

Package 'uuid' (dependency of '@remnux/mcp-server') has a known moderate vulnerability. Solo aplicable a servidores npm vía stdio. HTTP transport: no analizable.



**Evidence:**
```
uuid@<11.1.1 — no CVE assigned
```


**Remediation:** Update 'uuid' to a patched version.

---

### CORVUS-004 — Shadow Tool — 'run_tool' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `run_tool` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'run_tool' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
Execute a command in REMnux. Supports piped commands (e.g., 'oledump.py sample.doc | grep VBA'). String extraction: For PE files use 'pestr'; for non-PE use 'strings' (ASCII) and 'strings -el' (Unicode). Note: capa matches under namespaces like collection/* or data-manipulation/* can be artifact-lev
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-005 — Shadow Tool — 'analyze_file' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `analyze_file` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'analyze_file' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
Auto-analyze a file using REMnux tools appropriate for the detected file type. Runs `file` to detect type, then executes matching tools (e.g., PE → peframe/capa, PDF → pdfid/pdf-parser, Office → olevba/oleid). Use `depth` to control analysis intensity: 'quick' (triage only), 'standard' (default), 'd
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-006 — Resource URI — large attack surface (148 resources exposed)

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT05 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 60% |

The server exposes 148 MCP resources (threshold: 20). A large resource surface increases the risk of accidentally exposing sensitive data and makes it harder for operators to audit what information is accessible.



**Evidence:**
```
148 resources
```


**Remediation:** Audit each exposed resource for necessity. Apply the principle of least exposure — only surface resources that callers explicitly need.

---

### CORVUS-007 — Injection reflected — 'run_tool.command'

| Field | Value |
|-------|-------|
| Severity | **CRITICAL** |
| OWASP | MCP05 |
| Tool | `run_tool` |
| Parameter | `command` |
| Confidence | 92% |

SQL error keywords detected in response — error-based SQLi confirmed (field: command).


**Payload:**
```
; id
```


**Evidence:**
```
{
  "success": true,
  "tool": "run_tool",
  "data": {
    "command": "; id",
    "stdout": "",
    "stderr": "/bin/bash: -c: line 1: syntax error near unexpected token `;'\n/bin/bash: -c: line 1: `; id'",
    "exit_code": 2,
    "truncated": false
  },
  "metadata": {
    "elapsed_ms": 10484
  }
}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-008 — Injection reflected — 'run_tool.input_file'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `run_tool` |
| Parameter | `input_file` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: command).


**Payload:**
```
; id
```


**Evidence:**
```
{
  "success": true,
  "tool": "run_tool",
  "data": {
    "command": "test '/home/remnux/files/samples/; id'",
    "stdout": "",
    "stderr": "",
    "exit_code": 0,
    "truncated": false
  },
  "metadata": {
    "elapsed_ms": 313
  }
}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-009 — Token Exposure — home directory path in 'get_file_info'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP01 |
| Tool | `get_file_info` |
| Parameter | `—` |
| Confidence | 80% |

Tool response contains home directory path.



**Evidence:**
```
{
  "success": false,
  "tool": "get_file_info",
  "data": {},
  "error": "Could not verify file exists: /home/remnux/files/samples/test",
  "metadata": {
    "elapsed_ms": 12
  },
  "error_code": "FILE_NOT_FOUND",
  "error_category": "not_found",
  "remediation": "Check the filename with list_files, or upload the file first with upload_from_host"
}
```


**Remediation:** Strip sensitive data from tool responses. Never return raw environment variables, credentials, or internal paths.

---

### CORVUS-010 — Token Exposure — home directory path in 'analyze_file'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP01 |
| Tool | `analyze_file` |
| Parameter | `—` |
| Confidence | 80% |

Tool response contains home directory path.



**Evidence:**
```
{
  "success": false,
  "tool": "analyze_file",
  "data": {},
  "error": "Could not verify file exists: /home/remnux/files/samples/test",
  "metadata": {
    "elapsed_ms": 10
  },
  "error_code": "FILE_NOT_FOUND",
  "error_category": "not_found",
  "remediation": "Check the filename with list_files, or upload the file first with upload_from_host"
}
```


**Remediation:** Strip sensitive data from tool responses. Never return raw environment variables, credentials, or internal paths.

---

### CORVUS-011 — Token Exposure — home directory path in 'suggest_tools'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP01 |
| Tool | `suggest_tools` |
| Parameter | `—` |
| Confidence | 80% |

Tool response contains home directory path.



**Evidence:**
```
{
  "success": false,
  "tool": "suggest_tools",
  "data": {},
  "error": "Could not verify file exists: /home/remnux/files/samples/test",
  "metadata": {
    "elapsed_ms": 9
  },
  "error_code": "FILE_NOT_FOUND",
  "error_category": "not_found",
  "remediation": "Check the filename with list_files, or upload the file first with upload_from_host"
}
```


**Remediation:** Strip sensitive data from tool responses. Never return raw environment variables, credentials, or internal paths.

---

### CORVUS-012 — Token Exposure — home directory path in 'check_behavior_prerequisites'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP01 |
| Tool | `check_behavior_prerequisites` |
| Parameter | `—` |
| Confidence | 80% |

Tool response contains home directory path.



**Evidence:**
```
{
  "success": false,
  "tool": "check_behavior_prerequisites",
  "data": {},
  "error": "Could not verify file exists: /home/remnux/files/samples/test",
  "metadata": {
    "elapsed_ms": 10
  },
  "error_code": "FILE_NOT_FOUND",
  "error_category": "not_found",
  "remediation": "Check the filename with list_files, or upload the file first with upload_from_host"
}
```


**Remediation:** Strip sensitive data from tool responses. Never return raw environment variables, credentials, or internal paths.

---

### CORVUS-013 — Token Exposure — home directory path in 'verify_string_usage'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP01 |
| Tool | `verify_string_usage` |
| Parameter | `—` |
| Confidence | 80% |

Tool response contains home directory path.



**Evidence:**
```
{
  "success": false,
  "tool": "verify_string_usage",
  "data": {},
  "error": "Could not verify file exists: /home/remnux/files/samples/test",
  "metadata": {
    "elapsed_ms": 7
  },
  "error_code": "FILE_NOT_FOUND",
  "error_category": "not_found",
  "remediation": "Check the filename with list_files, or upload the file first with upload_from_host"
}
```


**Remediation:** Strip sensitive data from tool responses. Never return raw environment variables, credentials, or internal paths.

---

### CORVUS-014 — Token Exposure — home directory path in 'compare_files'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP01 |
| Tool | `compare_files` |
| Parameter | `—` |
| Confidence | 80% |

Tool response contains home directory path.



**Evidence:**
```
{
  "success": false,
  "tool": "compare_files",
  "data": {},
  "error": "Could not verify file exists: /home/remnux/files/samples/test",
  "metadata": {
    "elapsed_ms": 8
  },
  "error_code": "FILE_NOT_FOUND",
  "error_category": "not_found",
  "remediation": "Check the filename with list_files, or upload the file first with upload_from_host"
}
```


**Remediation:** Strip sensitive data from tool responses. Never return raw environment variables, credentials, or internal paths.

---

### CORVUS-015 — Protocol crash — oversized method name caused transport failure

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

### CORVUS-016 — Protocol crash — deeply nested params caused server disconnect

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

### CORVUS-017 — Protocol crash — string params caused server disconnect

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
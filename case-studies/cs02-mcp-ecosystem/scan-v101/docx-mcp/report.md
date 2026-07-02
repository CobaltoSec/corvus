# Corvus Security Scan Report

**Target:** `npx -y @usejunior/docx-mcp`
**Transport:** stdio
**Date:** 2026-07-02 14:52:35
**Duration:** 78.2s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | safe-docx |
| Version | 0.2.0 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 23 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 5 |
| MEDIUM | 18 |
| LOW | 41 |
| INFO | 5 |


**Total:** 69 finding(s)

---

## Findings



### CORVUS-001 — Scope Creep — 'save' accepts write-path param (path traversal risk)

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `save` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'save' accepts a file path parameter (file_path) and its description indicates write operations. Without path sanitization, callers may supply traversal sequences to write files outside the intended directory.



**Evidence:**
```
path param(s): file_path | description: Save document. For DOCX: saves clean and/or tracked changes output. For ODT: saves an .odt package. For Google Docs: checkpoint (default) returns revisionId, or snapshot exports as DOCX.
```


**Remediation:** Validate and canonicalize file path inputs. Restrict writes to an explicit base directory using path.resolve() or os.path.abspath() checks. Manual verification recommended.

---

### CORVUS-002 — Scope Creep — 'export' accepts write-path param (path traversal risk)

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `export` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'export' accepts a file path parameter (file_path, output_path) and its description indicates write operations. Without path sanitization, callers may supply traversal sequences to write files outside the intended directory.



**Evidence:**
```
path param(s): file_path, output_path | description: Export a document to a portable rendering (Markdown, semantic HTML, or plain text). Writes an output file (default: source path with the format extension, e.g. .md, .html, or .txt) and returns its pat
```


**Remediation:** Validate and canonicalize file path inputs. Restrict writes to an explicit base directory using path.resolve() or os.path.abspath() checks. Manual verification recommended.

---

### CORVUS-003 — Scope Creep — 'convert_to_odt' accepts write-path param (path traversal risk)

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `convert_to_odt` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'convert_to_odt' accepts a file path parameter (file_path, output_path) and its description indicates write operations. Without path sanitization, callers may supply traversal sequences to write files outside the intended directory.



**Evidence:**
```
path param(s): file_path, output_path | description: Convert a DOCX document to OpenDocument Text (.odt) using the native model-to-model converter (no LibreOffice involved). Writes the .odt (default: source path with the .odt extension), validates ODF p
```


**Remediation:** Validate and canonicalize file path inputs. Restrict writes to an explicit base directory using path.resolve() or os.path.abspath() checks. Manual verification recommended.

---

### CORVUS-004 — 'grep' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `grep` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-005 — 'export' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `export` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-006 — 'convert_to_odt' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `convert_to_odt` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-007 — 'format_layout' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `format_layout` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-008 — 'close_file' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `close_file` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-009 — Shadow Tool — 'read_file' conflicts with a high-value built-in name

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

### CORVUS-010 — Shadow Tool — 'batch_edit' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `batch_edit` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'batch_edit' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
Single-agent front door for applying multiple edit steps (replace_text, insert_paragraph) to a document in one call. Validates all steps first, rejects conflicts before applying anything, then executes valid steps sequentially. Accepts inline steps or a plan_file_path JSON array.
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-011 — Injection reflected — 'export.format'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `export` |
| Parameter | `format` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
{
  "success": false,
  "error": {
    "code": "INVALID_FORMAT",
    "message": "Invalid export format: <script>alert(1)</script>",
    "hint": "Supported formats: markdown, html, plaintext."
  }
}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-012 — 'read_file' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `read_file` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-013 — 'grep' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `grep` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-014 — 'batch_edit' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `batch_edit` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['file_path']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-015 — 'batch_edit.file_path' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `batch_edit` |
| Parameter | `file_path` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-016 — 'batch_edit' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `batch_edit` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-017 — 'replace_text' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `replace_text` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['target_paragraph_id', 'old_string', 'new_string', 'instruction']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-018 — 'replace_text.target_paragraph_id' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `replace_text` |
| Parameter | `target_paragraph_id` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-019 — 'replace_text' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `replace_text` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-020 — 'insert_paragraph' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `insert_paragraph` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['positional_anchor_node_id', 'new_string', 'instruction']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-021 — 'insert_paragraph.positional_anchor_node_id' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `insert_paragraph` |
| Parameter | `positional_anchor_node_id` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-022 — 'insert_paragraph' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `insert_paragraph` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-023 — 'save' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `save` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['save_to_local_path']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-024 — 'save.save_to_local_path' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `save` |
| Parameter | `save_to_local_path` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-025 — 'save' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `save` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-026 — 'export' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `export` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-027 — 'convert_to_odt' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `convert_to_odt` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-028 — 'format_layout' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `format_layout` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-029 — 'accept_changes' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `accept_changes` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['file_path']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-030 — 'accept_changes.file_path' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `accept_changes` |
| Parameter | `file_path` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-031 — 'accept_changes' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `accept_changes` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-032 — 'has_tracked_changes' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `has_tracked_changes` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['file_path']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-033 — 'has_tracked_changes.file_path' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `has_tracked_changes` |
| Parameter | `file_path` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-034 — 'has_tracked_changes' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `has_tracked_changes` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-035 — 'get_file_status' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_file_status` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-036 — 'close_file' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `close_file` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-037 — 'add_comment' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `add_comment` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['file_path', 'author', 'text']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-038 — 'add_comment.file_path' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `add_comment` |
| Parameter | `file_path` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-039 — 'add_comment' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `add_comment` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-040 — 'get_comments' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `get_comments` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['file_path']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-041 — 'get_comments.file_path' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_comments` |
| Parameter | `file_path` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-042 — 'get_comments' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_comments` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-043 — 'delete_comment' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `delete_comment` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['file_path', 'comment_id']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-044 — 'delete_comment.file_path' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `delete_comment` |
| Parameter | `file_path` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-045 — 'delete_comment' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `delete_comment` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-046 — 'compare_documents' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `compare_documents` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['save_to_local_path']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-047 — 'compare_documents.save_to_local_path' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `compare_documents` |
| Parameter | `save_to_local_path` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-048 — 'compare_documents' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `compare_documents` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-049 — 'get_footnotes' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `get_footnotes` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['file_path']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-050 — 'get_footnotes.file_path' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_footnotes` |
| Parameter | `file_path` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-051 — 'get_footnotes' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_footnotes` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-052 — 'add_footnote' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `add_footnote` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['file_path', 'target_paragraph_id', 'text']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-053 — 'add_footnote.file_path' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `add_footnote` |
| Parameter | `file_path` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-054 — 'add_footnote' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `add_footnote` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-055 — 'update_footnote' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `update_footnote` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['file_path', 'note_id', 'new_text']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-056 — 'update_footnote.file_path' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `update_footnote` |
| Parameter | `file_path` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-057 — 'update_footnote' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `update_footnote` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-058 — 'delete_footnote' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `delete_footnote` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['file_path', 'note_id']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-059 — 'delete_footnote.file_path' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `delete_footnote` |
| Parameter | `file_path` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-060 — 'delete_footnote' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `delete_footnote` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-061 — 'clear_formatting' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `clear_formatting` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['file_path']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-062 — 'clear_formatting.file_path' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `clear_formatting` |
| Parameter | `file_path` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-063 — 'clear_formatting' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `clear_formatting` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-064 — 'extract_revisions' accepts missing required fields

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT01 |
| Tool | `extract_revisions` |
| Parameter | `—` |
| Confidence | 80% |

Tool succeeded with empty arguments despite required: ['file_path']




**Remediation:** Validate that all required parameters are present before processing.

---

### CORVUS-065 — 'extract_revisions.file_path' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `extract_revisions` |
| Parameter | `file_path` |
| Confidence | 80% |

Expected type 'string', sent NoneType value 'None' — no error returned.


**Payload:**
```
None
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-066 — 'extract_revisions' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `extract_revisions` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-067 — initialize accepts protocol version downgrade

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

### CORVUS-068 — Null request ID accepted — JSON-RPC spec violation

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

### CORVUS-069 — Protocol crash — string params caused server disconnect

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
# Corvus Security Scan Report

**Target:** `uvx arxiv-mcp-server`
**Transport:** stdio
**Date:** 2026-07-03 13:21:41
**Duration:** 151.5s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | arxiv-mcp-server |
| Version | 0.5.0 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 10 |
| Resources | 0 |
| Prompts | 7 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 5 |
| LOW | 2 |
| INFO | 3 |


**Total:** 12 finding(s)

---

## Findings



### CORVUS-001 — Scope Creep — 'read_paper' is named read-only but description implies write access

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP02 |
| Tool | `read_paper` |
| Parameter | `—` |
| Confidence | 70% |

Tool 'read_paper' has a read-only prefix but its description mentions write operations ('clear'), creating a scope mismatch that callers and LLMs may be unable to detect.



**Evidence:**
```
Read the full text content of a paper that was previously downloaded via download_paper. Returns the paper in markdown format. Will fail with a clear error if the paper has not been downloaded yet — call download_paper first. Workflow: search_papers -> download_paper -> read_paper.
```


**Remediation:** Separate read and write operations into distinct tools. Ensure tool names accurately reflect their full capabilities.

---

### CORVUS-002 — Excessive description length in 'search_papers'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP03 |
| Tool | `search_papers` |
| Parameter | `—` |
| Confidence | 80% |

Description is 3053 chars (limit 1000). May contain hidden content.




**Remediation:** Keep descriptions concise; review for hidden instructions.

---

### CORVUS-003 — High entropy description in 'search_papers'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP03 |
| Tool | `search_papers` |
| Parameter | `—` |
| Confidence | 20% |

Unusual character distribution may indicate obfuscated content.




**Remediation:** Review description for base64-encoded or otherwise obfuscated payloads.

---

### CORVUS-004 — 'reindex' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `reindex` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-005 — 'check_alerts' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `check_alerts` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-006 — Tool Chaining — 'semantic_search' directs LLM to call search_papers

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT06 |
| Tool | `semantic_search` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'semantic_search' description references tool(s) 'search_papers', 'download_paper' from the same server using imperative language. This pattern can force an LLM into an unintended call chain or manufacture urgency to invoke a privileged tool.



**Evidence:**
```
Semantic similarity search over papers you have already downloaded locally via download_paper. Supports free-text queries (e.g. 'attention mechanisms for long sequences') or finding papers similar to a given paper_id. IMPORTANT: only searches your local downloaded collection — will return empty resu
```


**Remediation:** Tool descriptions should describe what the tool does — not instruct the LLM on what other tools to call. Remove cross-tool directives and let the caller decide the execution order.

---

### CORVUS-007 — Tool Chaining — 'check_alerts' directs LLM to call watch_topic

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT06 |
| Tool | `check_alerts` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'check_alerts' description references tool(s) 'watch_topic' from the same server using imperative language. This pattern can force an LLM into an unintended call chain or manufacture urgency to invoke a privileged tool.



**Evidence:**
```
Check all saved topic watches for newly published papers since the last check. Omitting the topic parameter runs ALL saved watches and returns new papers for each. Passing a topic string checks only that specific watch. Updates each watch's last_checked timestamp after running, so subsequent calls o
```


**Remediation:** Tool descriptions should describe what the tool does — not instruct the LLM on what other tools to call. Remove cross-tool directives and let the caller decide the execution order.

---

### CORVUS-008 — Injection reflected — 'watch_topic.topic'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `watch_topic` |
| Parameter | `topic` |
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
  "message": "Topic watch saved",
  "topic": {
    "topic": "' OR '1'='1",
    "categories": [],
    "max_results": 10,
    "last_checked": null,
    "created_at": "2026-07-03T16:20:42.110615+00:00",
    "updated_at": "2026-07-03T16:20:42.110634+00:00"
  }
}
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

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

### CORVUS-012 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

9 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---



*Generated by [Corvus](https://github.com/CobaltoSec/corvus)*
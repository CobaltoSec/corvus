# Corvus Security Scan Report

**Target:** `https://vaaya.ai/mcp`
**Transport:** http
**Date:** 2026-07-28 16:55:08
**Duration:** 22.4s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | vaaya |
| Version | 1.0.0 |
| Protocol | 2025-06-18 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 9 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 11 |
| LOW | 2 |
| INFO | 2 |


**Total:** 17 finding(s)

---

## Findings



### CORVUS-001 — Excessive description length in 'consult'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP03 |
| Tool | `consult` |
| Parameter | `—` |
| Confidence | 80% |

Description is 1362 chars (limit 1000). May contain hidden content.




**Remediation:** Keep descriptions concise; review for hidden instructions.

---

### CORVUS-002 — Shadow Tool — 'consult' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `consult` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'consult' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
Vaaya's consultant. Describe ANY external capability you or the user might want — generate an image/video, search or scrape the web, run code in a sandbox, send/receive email, enrich a contact — and it helps figure out the best way, teaching the user what Vaaya can do. It is CONVERSATIONAL and remem
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-003 — Shadow Tool — 'use' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `use` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'use' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
Execute a single call that `consult` handed you, and bill on success. Used for any external capability (image/video/audio generation, web search, scraping, email, document parsing, code sandbox, browser automation, embeddings, etc.). The server validates params against a registered schema and proxie
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-004 — Tool Chaining — 'consult' directs LLM to call use

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT06 |
| Tool | `consult` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'consult' description references tool(s) 'use', 'result' from the same server using imperative language. This pattern can force an LLM into an unintended call chain or manufacture urgency to invoke a privileged tool.



**Evidence:**
```
Vaaya's consultant. Describe ANY external capability you or the user might want — generate an image/video, search or scrape the web, run code in a sandbox, send/receive email, enrich a contact — and it helps figure out the best way, teaching the user what Vaaya can do. It is CONVERSATIONAL and remem
```


**Remediation:** Tool descriptions should describe what the tool does — not instruct the LLM on what other tools to call. Remove cross-tool directives and let the caller decide the execution order.

---

### CORVUS-005 — Tool Chaining — 'use' directs LLM to call consult

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT06 |
| Tool | `use` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'use' description references tool(s) 'consult' from the same server using imperative language. This pattern can force an LLM into an unintended call chain or manufacture urgency to invoke a privileged tool.



**Evidence:**
```
Execute a single call that `consult` handed you, and bill on success. Used for any external capability (image/video/audio generation, web search, scraping, email, document parsing, code sandbox, browser automation, embeddings, etc.). The server validates params against a registered schema and proxie
```


**Remediation:** Tool descriptions should describe what the tool does — not instruct the LLM on what other tools to call. Remove cross-tool directives and let the caller decide the execution order.

---

### CORVUS-006 — Tool Chaining — 'result' directs LLM to call use

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT06 |
| Tool | `result` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'result' description references tool(s) 'use' from the same server using imperative language. This pattern can force an LLM into an unintended call chain or manufacture urgency to invoke a privileged tool.



**Evidence:**
```
Fetch the status + output of an async job started by `use` (e.g. a video render). Pass the `job_id` that `use` returned with `{ async: true }`. Returns `{ status, result?, progress?, charged_cents }`: `running` (still working — when the job reports it, `progress` carries `{ phase, percent, rendered_
```


**Remediation:** Tool descriptions should describe what the tool does — not instruct the LLM on what other tools to call. Remove cross-tool directives and let the caller decide the execution order.

---

### CORVUS-007 — Tool Chaining — 'session' directs LLM to call use

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT06 |
| Tool | `session` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'session' description references tool(s) 'use', 'result', 'close' from the same server using imperative language. This pattern can force an LLM into an unintended call chain or manufacture urgency to invoke a privileged tool.



**Evidence:**
```
Run a command or code in an open E2B sandbox session (started by `use` with action `create_session`, which returns a `session_id`). Pass `session_id` plus either `command` (a shell command) or `code` (+ optional `language`: python/javascript/bash). Returns stdout/stderr/exit_code (or the code result
```


**Remediation:** Tool descriptions should describe what the tool does — not instruct the LLM on what other tools to call. Remove cross-tool directives and let the caller decide the execution order.

---

### CORVUS-008 — Tool Chaining — 'close' directs LLM to call session

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT06 |
| Tool | `close` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'close' description references tool(s) 'session' from the same server using imperative language. This pattern can force an LLM into an unintended call chain or manufacture urgency to invoke a privileged tool.



**Evidence:**
```
Close an E2B sandbox session and stop its billing. Pass the `session_id`. Captures the final metered uptime cost and releases the hold. ALWAYS call this when finished with a session — an open session keeps billing per second of uptime. Safe to call repeatedly (idempotent).
```


**Remediation:** Tool descriptions should describe what the tool does — not instruct the LLM on what other tools to call. Remove cross-tool directives and let the caller decide the execution order.

---

### CORVUS-009 — Token Exposure — server version disclosure in HTTP response headers

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | MCP01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 75% |

HTTP response header 'server: Vercel' discloses internal information.



**Evidence:**
```
server: Vercel
```


**Remediation:** Remove the 'server' response header in production.

---

### CORVUS-010 — initialize accepts protocol version downgrade

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

### CORVUS-011 — initialize crash — missing protocolVersion causes unhandled error

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP07 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 70% |

Sending initialize without the required protocolVersion field caused the server to crash or return an unexpected result. Servers must validate required fields and return -32602 (Invalid params).



**Evidence:**
```
initialize({capabilities:{}, clientInfo:{...}}) — no protocolVersion
```


**Remediation:** Add required-field validation to the initialize handler.

---

### CORVUS-012 — initialize accepts type-confused protocolVersion (integer instead of string)

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP07 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 65% |

The server accepted an initialize request where protocolVersion was an integer (42) instead of a string. Strict type checking prevents parser confusion and unexpected coercion behavior.



**Evidence:**
```
protocolVersion: 42 (integer) → server returned serverInfo
```


**Remediation:** Validate that protocolVersion is a string before processing.

---

### CORVUS-013 — Null request ID accepted — JSON-RPC spec violation

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

### CORVUS-014 — Server accepts requests without jsonrpc field

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

### CORVUS-015 — Server accepts array request ID — JSON-RPC spec violation

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

### CORVUS-016 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

5 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

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



*Generated by [Corvus](https://github.com/CobaltoSec/corvus)*
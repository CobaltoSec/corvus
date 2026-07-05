# Corvus Security Scan Report

**Target:** `uvx arxiv-research-mcp`
**Transport:** stdio
**Date:** 2026-07-05 20:17:09
**Duration:** 45.4s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | arxiv-research |
| Version | 1.28.1 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 4 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 4 |
| MEDIUM | 6 |
| LOW | 2 |
| INFO | 1 |


**Total:** 13 finding(s)

---

## Findings



### CORVUS-001 — Excessive description length in 'trending_topics'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP03 |
| Tool | `trending_topics` |
| Parameter | `—` |
| Confidence | 80% |

Description is 1203 chars (limit 1000). May contain hidden content.




**Remediation:** Keep descriptions concise; review for hidden instructions.

---

### CORVUS-002 — Tool Chaining — 'get_abstract' directs LLM to call search_papers

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT06 |
| Tool | `get_abstract` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'get_abstract' description references tool(s) 'search_papers', 'find_by_author', 'trending_topics' from the same server using imperative language. This pattern can force an LLM into an unintended call chain or manufacture urgency to invoke a privileged tool.



**Evidence:**
```
Fetch the full details of a single arXiv paper by its ID.

Use this when you already know a paper's arXiv ID (for example, one returned
by ``search_papers``, ``find_by_author``, or ``trending_topics``, or pasted
by the user) and need its complete record: the full untruncated abstract,
the complete a
```


**Remediation:** Tool descriptions should describe what the tool does — not instruct the LLM on what other tools to call. Remove cross-tool directives and let the caller decide the execution order.

---

### CORVUS-003 — Tool Chaining — 'trending_topics' directs LLM to call search_papers

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT06 |
| Tool | `trending_topics` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'trending_topics' description references tool(s) 'search_papers' from the same server using imperative language. This pattern can force an LLM into an unintended call chain or manufacture urgency to invoke a privileged tool.



**Evidence:**
```
Surface what is being actively published in an arXiv category right now.

Use this to answer "what's hot / trending in <field> this week?" or to get a
pulse on a research area. It scans the most recent submissions to a single
category, keeps those within the last ``days`` days, returns them newest
f
```


**Remediation:** Tool descriptions should describe what the tool does — not instruct the LLM on what other tools to call. Remove cross-tool directives and let the caller decide the execution order.

---

### CORVUS-004 — Injection reflected — 'search_papers.query'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `search_papers` |
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
  "query": "' OR '1'='1",
  "sort_by": "relevance",
  "returned": 10,
  "response_format": "concise",
  "papers": [
    {
      "arxiv_id": "1603.07035v1",
      "title": "Revisiting Unit Fractions That Sum To 1",
      "authors": [
        "Yutaka Nishiyama"
      ],
      "author_count": 1,
    
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-005 — Slow tool response — 'search_papers' took 13.7s

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP10 |
| Tool | `search_papers` |
| Parameter | `—` |
| Confidence | 70% |

Tool 'search_papers' took 13.7 seconds to respond. Slow responses can be used for resource exhaustion in agent pipelines or indicate unbounded computation triggered by benign inputs.



**Evidence:**
```
Response time: 13.69s
```


**Remediation:** Enforce server-side timeouts on all tool executions. Cap at 30s max.

---

### CORVUS-006 — Response Flooding — 'search_papers' returns oversized response

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP10 |
| Tool | `search_papers` |
| Parameter | `—` |
| Confidence | 85% |

Tool 'search_papers' returned 10,111 bytes (threshold: 8,192 bytes). Large responses can overflow LLM context windows, push out system prompts, or cause denial-of-service in agent pipelines.



**Evidence:**
```
10,111 bytes — preview: {
  "query": "test",
  "sort_by": "relevance",
  "returned": 10,
  "response_format": "concise",
  "papers": [
    {
      "arxiv_id": "1101.4081v3",
      "title": "A simple way to speedup Gauss Elim
```


**Remediation:** Paginate or cap tool responses. Never return unbounded data. Aim for responses under 4 KB to preserve LLM context budget.

---

### CORVUS-007 — SSRF (timeout) — 'search_papers.query' hung on SSRF payload

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT04 |
| Tool | `search_papers` |
| Parameter | `query` |
| Confidence | 65% |

Call with SSRF payload 'http://169.254.169.254/latest/meta-data/' timed out after 12.0s, suggesting the server is attempting the network request.


**Payload:**
```
http://169.254.169.254/latest/meta-data/
```



**Remediation:** Block outbound requests to RFC-1918 and link-local ranges. Use an allowlist for permitted URL schemes and hosts.

---

### CORVUS-008 — initialize accepts protocol version downgrade

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP07 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 75% |

The server accepted initialize with arbitrary protocol versions: ['9999-99-99']. The server also accepted far-future versions, indicating no version validation at all. Servers should reject versions outside their supported range to prevent feature-downgrade attacks.



**Evidence:**
```
Accepted versions: ['9999-99-99']
```


**Remediation:** Validate protocolVersion against a supported range. Return a JSON-RPC error for versions outside that range.

---

### CORVUS-009 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

4 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---

### CORVUS-010 — Protocol crash — JSON-RPC batch array caused server disconnect

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
Server disconnected after batch. Pre-crash response: none
```


**Remediation:** Validate input type at the JSON-RPC layer: if the parsed value is a list, return -32600 (Invalid Request) immediately without further processing.

---

### CORVUS-011 — Protocol crash — oversized method name caused transport failure

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

### CORVUS-012 — Protocol crash — deeply nested params caused server disconnect

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

### CORVUS-013 — Protocol crash — string params caused server disconnect

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
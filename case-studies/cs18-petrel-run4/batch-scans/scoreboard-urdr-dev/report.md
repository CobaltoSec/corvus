# Corvus Security Scan Report

**Target:** `https://scoreboard.urdr.dev/api/mcp`
**Transport:** http
**Date:** 2026-07-28 16:58:06
**Duration:** 13.6s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | ssi-scoreboard |
| Version | 0.1.0 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 7 |
| Resources | 2 |
| Prompts | 4 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 7 |
| LOW | 0 |
| INFO | 3 |


**Total:** 11 finding(s)

---

## Findings



### CORVUS-001 — Scope Creep — 'get_match' claims unrestricted access scope

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP02 |
| Tool | `get_match` |
| Parameter | `—` |
| Confidence | 85% |

Tool 'get_match' description contains a broad-scope claim: 'any user'. Unrestricted scope tools risk being exploited for lateral movement or privilege escalation in an MCP session.



**Evidence:**
```
Fetch full details for a specific IPSC match. Returns the complete competitor list — each entry has a numeric `id`, `name`, `club`, and `division`. Also returns a `squads` list where each squad has a `name` (e.g. 'Squad 3') and a `competitorIds` array of every competitor in that squad. Use this to r
```


**Remediation:** Scope tools to the minimum necessary access. Replace 'any path' / 'all files' with explicit allowlists. Validate and restrict inputs server-side.

---

### CORVUS-002 — Excessive description length in 'get_match'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP03 |
| Tool | `get_match` |
| Parameter | `—` |
| Confidence | 80% |

Description is 1098 chars (limit 1000). May contain hidden content.




**Remediation:** Keep descriptions concise; review for hidden instructions.

---

### CORVUS-003 — Excessive description length in 'compare_competitors'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP03 |
| Tool | `compare_competitors` |
| Parameter | `—` |
| Confidence | 80% |

Description is 1067 chars (limit 1000). May contain hidden content.




**Remediation:** Keep descriptions concise; review for hidden instructions.

---

### CORVUS-004 — 'find_shooter' defines no required fields

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT02 |
| Tool | `find_shooter` |
| Parameter | `—` |
| Confidence | 70% |

All parameters are implicitly optional. Verify this is intentional.




**Remediation:** Declare required parameters explicitly to enforce correct usage.

---

### CORVUS-005 — Tool Chaining — 'get_match' directs LLM to call search_events

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT06 |
| Tool | `get_match` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'get_match' description references tool(s) 'search_events' from the same server using imperative language. This pattern can force an LLM into an unintended call chain or manufacture urgency to invoke a privileged tool.



**Evidence:**
```
Fetch full details for a specific IPSC match. Returns the complete competitor list — each entry has a numeric `id`, `name`, `club`, and `division`. Also returns a `squads` list where each squad has a `name` (e.g. 'Squad 3') and a `competitorIds` array of every competitor in that squad. Use this to r
```


**Remediation:** Tool descriptions should describe what the tool does — not instruct the LLM on what other tools to call. Remove cross-tool directives and let the caller decide the execution order.

---

### CORVUS-006 — Tool Chaining — 'compare_competitors' directs LLM to call get_match

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | EXT06 |
| Tool | `compare_competitors` |
| Parameter | `—` |
| Confidence | 65% |

Tool 'compare_competitors' description references tool(s) 'get_match' from the same server using imperative language. This pattern can force an LLM into an unintended call chain or manufacture urgency to invoke a privileged tool.



**Evidence:**
```
Run a deep stage-by-stage comparison for 1–12 competitors in a match. Returns scores, hit factors, penalties, efficiency %, consistency, time-vs-accuracy breakdown, what-if rank simulations, and performance fingerprints. Pass a single competitor ID to analyse one shooter in isolation. Pass multiple 
```


**Remediation:** Tool descriptions should describe what the tool does — not instruct the LLM on what other tools to call. Remove cross-tool directives and let the caller decide the execution order.

---

### CORVUS-007 — Token Exposure — server version disclosure in HTTP response headers

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | MCP01 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 75% |

HTTP response header 'server: cloudflare' discloses internal information.



**Evidence:**
```
server: cloudflare
```


**Remediation:** Remove the 'server' response header in production.

---

### CORVUS-008 — initialize accepts protocol version downgrade

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

### CORVUS-009 — Null request ID accepted — JSON-RPC spec violation

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

### CORVUS-010 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

6 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---

### CORVUS-011 — Server accepts path traversal cursor without validation

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
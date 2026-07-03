# Corvus Security Scan Report

**Target:** `npx -y european-parliament-mcp-server`
**Transport:** stdio
**Date:** 2026-07-02 23:26:42
**Duration:** 15.9s
**Modules:** github-advisory, npm-behavior, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | european-parliament-mcp-server |
| Version | 1.3.34 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 63 |
| Resources | 0 |
| Prompts | 7 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 3 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 3 |


**Total:** 7 finding(s)

---

## Findings



### CORVUS-001 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

62 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---

### CORVUS-002 — Prompt template injection confirmed in 'mep_briefing'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT12 |
| Tool | `mep_briefing` |
| Parameter | `—` |
| Confidence | 88% |

prompts/get for 'mep_briefing' reflected the injection payload verbatim in the returned messages, confirming unsanitized argument reflection.


**Payload:**
```
CORVUS_INJECTION_TEST_{{7*7}}
```


**Evidence:**
```
Payload reflected in messages: {"description": "MEP Intelligence Briefing for CORVUS_INJECTION_TEST_{{7*7}}", "messages": [{"role": "user", "content": {"type": "text", "text": "Generate a comprehensive intelligence briefing for MEP CORVUS_INJECTION_TEST_{{7*7}} covering the CORVUS_INJECTION_TEST_{{7*7}} period.\n\nUse these Europ
```


**Remediation:** Sanitize prompt arguments before embedding them in message templates.

---

### CORVUS-003 — Prompt template injection confirmed in 'coalition_analysis'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT12 |
| Tool | `coalition_analysis` |
| Parameter | `—` |
| Confidence | 88% |

prompts/get for 'coalition_analysis' reflected the injection payload verbatim in the returned messages, confirming unsanitized argument reflection.


**Payload:**
```
CORVUS_INJECTION_TEST_{{7*7}}
```


**Evidence:**
```
Payload reflected in messages: {"description": "Coalition dynamics analysis for CORVUS_INJECTION_TEST_{{7*7}}", "messages": [{"role": "user", "content": {"type": "text", "text": "Analyze coalition dynamics in the European Parliament for CORVUS_INJECTION_TEST_{{7*7}} during CORVUS_INJECTION_TEST_{{7*7}}.\n\nUse these MCP tools:\n1
```


**Remediation:** Sanitize prompt arguments before embedding them in message templates.

---

### CORVUS-004 — Prompt template injection confirmed in 'legislative_tracking'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT12 |
| Tool | `legislative_tracking` |
| Parameter | `—` |
| Confidence | 88% |

prompts/get for 'legislative_tracking' reflected the injection payload verbatim in the returned messages, confirming unsanitized argument reflection.


**Payload:**
```
CORVUS_INJECTION_TEST_{{7*7}}
```


**Evidence:**
```
Payload reflected in messages: {"description": "Legislative tracking for procedure CORVUS_INJECTION_TEST_{{7*7}}, committee CORVUS_INJECTION_TEST_{{7*7}}", "messages": [{"role": "user", "content": {"type": "text", "text": "Track and analyze the legislative pipeline for procedure CORVUS_INJECTION_TEST_{{7*7}}, committee CORVUS_INJ
```


**Remediation:** Sanitize prompt arguments before embedding them in message templates.

---

### CORVUS-005 — Server accepts path traversal cursor without validation

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

### CORVUS-006 — Server correctly ignores cancellation of unknown request

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT14 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

The server remained responsive after receiving notifications/cancelled for a non-existent request.




**Remediation:** No action required — correct behavior.

---

### CORVUS-007 — Cancellation race condition timing detected — server responded normally

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT14 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 70% |

The request/cancel race did not cause a hang; the server responded to one of the two messages.




**Remediation:** No action required — server handled the race gracefully.

---



*Generated by [Corvus](https://github.com/CobaltoSec/corvus)*
# Corvus Security Scan Report

**Target:** `npx -y @jpisnice/shadcn-ui-mcp-server`
**Transport:** stdio
**Date:** 2026-07-02 23:25:30
**Duration:** 10.4s
**Modules:** github-advisory, npm-behavior, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | shadcn-ui-mcp-server |
| Version | 2.0.0 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 10 |
| Resources | 2 |
| Prompts | 5 |

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

8 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---

### CORVUS-002 — Prompt template injection confirmed in 'build-shadcn-page'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT12 |
| Tool | `build-shadcn-page` |
| Parameter | `—` |
| Confidence | 88% |

prompts/get for 'build-shadcn-page' reflected the injection payload verbatim in the returned messages, confirming unsanitized argument reflection.


**Payload:**
```
CORVUS_INJECTION_TEST_{{7*7}}
```


**Evidence:**
```
Payload reflected in messages: {"messages": [{"role": "user", "content": {"type": "text", "text": "Create a complete CORVUS_INJECTION_TEST_{{7*7}} page using shadcn/ui v4 components and blocks for react. \n\nREQUIREMENTS:\n- Framework: react\n- Page Type: CORVUS_INJECTION_TEST_{{7*7}}\n- Features: CORVUS_INJECTION_TEST_{{7*7}}\n-
```


**Remediation:** Sanitize prompt arguments before embedding them in message templates.

---

### CORVUS-003 — Prompt template injection confirmed in 'create-dashboard'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT12 |
| Tool | `create-dashboard` |
| Parameter | `—` |
| Confidence | 88% |

prompts/get for 'create-dashboard' reflected the injection payload verbatim in the returned messages, confirming unsanitized argument reflection.


**Payload:**
```
CORVUS_INJECTION_TEST_{{7*7}}
```


**Evidence:**
```
Payload reflected in messages: {"messages": [{"role": "user", "content": {"type": "text", "text": "Create a comprehensive CORVUS_INJECTION_TEST_{{7*7}} dashboard using shadcn/ui v4 blocks and components for react.\n\nREQUIREMENTS:\n- Framework: react\n- Dashboard Type: CORVUS_INJECTION_TEST_{{7*7}}\n- Widgets: CORVUS_INJECTION_TE
```


**Remediation:** Sanitize prompt arguments before embedding them in message templates.

---

### CORVUS-004 — Prompt template injection confirmed in 'create-auth-flow'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT12 |
| Tool | `create-auth-flow` |
| Parameter | `—` |
| Confidence | 88% |

prompts/get for 'create-auth-flow' reflected the injection payload verbatim in the returned messages, confirming unsanitized argument reflection.


**Payload:**
```
CORVUS_INJECTION_TEST_{{7*7}}
```


**Evidence:**
```
Payload reflected in messages: {"messages": [{"role": "user", "content": {"type": "text", "text": "Create a complete CORVUS_INJECTION_TEST_{{7*7}} authentication flow using shadcn/ui v4 login blocks and components for react.\n\nREQUIREMENTS:\n- Framework: react\n- Auth Type: CORVUS_INJECTION_TEST_{{7*7}}\n- Providers: CORVUS_INJE
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
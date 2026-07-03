# Corvus Security Scan Report

**Target:** `npx -y @taiyokimura/nextjs-docs-mcp@latest`
**Transport:** stdio
**Date:** 2026-07-03 16:34:29
**Duration:** 58.4s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | nextjs-docs-mcp |
| Version | 1.0.0 |
| Protocol | 2024-11-05 |

## Attack Surface

| Type | Count |
|------|-------|
| Tools | 1 |
| Resources | 0 |
| Prompts | 0 |

---

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 4 |
| LOW | 2 |
| INFO | 1 |


**Total:** 8 finding(s)

---

## Findings



### CORVUS-001 — Excessive description length in 'get_all_docs'

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP03 |
| Tool | `get_all_docs` |
| Parameter | `—` |
| Confidence | 80% |

Description is 1207 chars (limit 1000). May contain hidden content.




**Remediation:** Keep descriptions concise; review for hidden instructions.

---

### CORVUS-002 — 'get_all_docs' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_all_docs` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-003 — Response Flooding — 'get_all_docs' returns oversized response

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP10 |
| Tool | `get_all_docs` |
| Parameter | `—` |
| Confidence | 85% |

Tool 'get_all_docs' returned 28,433 bytes (threshold: 8,192 bytes). Large responses can overflow LLM context windows, push out system prompts, or cause denial-of-service in agent pipelines.



**Evidence:**
```
28,433 bytes — preview: 📚 **Next.js Documentation - All Available Documents**

Total documents: 170

以下は全てのNext.jsドキュメントURLです。あなたのクエリに関連するドキュメントをこれらの中から選んでください：

1. **Quick Start**
   📁 Category: gettingStarted
   🔗 https://
```


**Remediation:** Paginate or cap tool responses. Never return unbounded data. Aim for responses under 4 KB to preserve LLM context budget.

---

### CORVUS-004 — Response Flooding — 'get_all_docs' returns highly repetitive content

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP10 |
| Tool | `get_all_docs` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'get_all_docs' response contains a phrase repeated ≥15 times. Repetitive content can be used to anchor specific instructions into LLM memory or exhaust context budget with low-information noise.



**Evidence:**
```
📚 **Next.js Documentation - All Available Documents**

Total documents: 170

以下は全てのNext.jsドキュメントURLです。あなたのクエリに関連するドキュメントをこれらの中から選んでください：

1. **Quick Start**
   📁 Category: gettingStarted
   🔗 https://nextjs.org/docs/getting-started
   📝 Get started with Next.js

2. **Installation**
   📁 Category: ge
```


**Remediation:** Deduplicate response data. Avoid returning the same value or phrase more than a handful of times in a single response.

---

### CORVUS-005 — initialize accepts protocol version downgrade

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

### CORVUS-006 — Null request ID accepted — JSON-RPC spec violation

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

### CORVUS-007 — Protocol crash — string params caused server disconnect

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

### CORVUS-008 — MCP server exposes tools with completable arguments

| Field | Value |
|-------|-------|
| Severity | **INFO** |
| OWASP | EXT10 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 90% |

1 tool(s) have schema properties that may support completion/complete enumeration.




**Remediation:** Review which argument values are exposed via completion/complete.

---



*Generated by [Corvus](https://github.com/CobaltoSec/corvus)*
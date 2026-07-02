# Corvus Security Scan Report

**Target:** `npx -y mcp-server-docker`
**Transport:** stdio
**Date:** 2026-07-02 14:54:13
**Duration:** 57.2s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | mcp-server-docker |
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
| HIGH | 3 |
| MEDIUM | 3 |
| LOW | 3 |
| INFO | 0 |


**Total:** 9 finding(s)

---

## Findings



### CORVUS-001 — Supply Chain — '@modelcontextprotocol/sdk' has high vulnerability (no CVE assigned)

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP04 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 65% |

Package '@modelcontextprotocol/sdk' (dependency of 'mcp-server-docker') has a known high vulnerability. Solo aplicable a servidores npm vía stdio. HTTP transport: no analizable.



**Evidence:**
```
@modelcontextprotocol/sdk@<=1.25.1 — no CVE assigned
```


**Remediation:** Update '@modelcontextprotocol/sdk' to a patched version.

---

### CORVUS-002 — Supply Chain — 'uuid' has moderate vulnerability (no CVE assigned)

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP04 |
| Tool | `—` |
| Parameter | `—` |
| Confidence | 65% |

Package 'uuid' (dependency of 'mcp-server-docker') has a known moderate vulnerability. Solo aplicable a servidores npm vía stdio. HTTP transport: no analizable.



**Evidence:**
```
uuid@<11.1.1 — no CVE assigned
```


**Remediation:** Update 'uuid' to a patched version.

---

### CORVUS-003 — Shadow Tool — 'run_command' conflicts with a high-value built-in name

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `run_command` |
| Parameter | `—` |
| Confidence | 90% |

Tool 'run_command' uses a name commonly associated with built-in or high-privilege operations. A malicious server could register this tool to shadow legitimate tools and intercept LLM actions.




**Remediation:** Rename the tool to something unique and context-specific. Avoid generic names like 'bash', 'execute', or 'read_file' that clash with well-known tool namespaces.

---

### CORVUS-004 — Shadow Tool — 'run_command' description reveals arbitrary execution intent

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | EXT03 |
| Tool | `run_command` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'run_command' description contains keywords associated with arbitrary command or shell execution. This may enable sandbox escape or privilege escalation.



**Evidence:**
```
Execute a command inside a Docker container service
```


**Remediation:** Restrict the tool to a well-defined, scoped operation. Do not expose generic shell execution capabilities via MCP tools.

---

### CORVUS-005 — 'run_command.command' silently accepts wrong type

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `run_command` |
| Parameter | `command` |
| Confidence | 80% |

Expected type 'string', sent int value '12345' — no error returned.


**Payload:**
```
12345
```



**Remediation:** Validate parameter types strictly and return clear JSON-RPC errors on mismatch.

---

### CORVUS-006 — 'run_command' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `run_command` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-007 — initialize accepts protocol version downgrade

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

### CORVUS-008 — Null request ID accepted — JSON-RPC spec violation

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

### CORVUS-009 — Protocol crash — string params caused server disconnect

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
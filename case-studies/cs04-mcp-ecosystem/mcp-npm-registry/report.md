# Corvus Security Scan Report

**Target:** `npx -y mcp-npm-registry`
**Transport:** stdio
**Date:** 2026-07-03 16:27:33
**Duration:** 101.7s
**Modules:** scope-audit, supply-chain, supply-chain-python, osv-supply-chain, github-advisory, npm-behavior, tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit, resource-uri, tool-chaining, batch-dos, cmd-injection, token-exposure, schema-bypass, response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling, init-audit, proto-fuzz, output-encoding, response-injection, oauth-bypass, sampling-probe, elicitation-probe, completion-probe, logging-probe, prompts-injection, cursor-probe, cancellation-probe

---

## Server Info

| Field | Value |
|-------|-------|
| Name | mcp-npm-registry |
| Version | 1.0.0 |
| Protocol | 2024-11-05 |

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
| HIGH | 7 |
| MEDIUM | 3 |
| LOW | 18 |
| INFO | 1 |


**Total:** 29 finding(s)

---

## Findings



### CORVUS-001 — Injection reflected — 'search_packages.query'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `search_packages` |
| Parameter | `query` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: sql).


**Payload:**
```
' OR '1'='1
```


**Evidence:**
```
Found 1425775 packages for "' OR '1'='1". Top 5:

📦 **ieee754** v1.2.1
   Read/write IEEE754 floating point numbers from/to a Buffer or array-like object
   🔗 https://www.npmjs.com/package/ieee754
   Score — quality: 100%  maintenance: 100%  popularity: 100%
   Last published: 27/10/2020

📦 **wbuf**
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-002 — Injection reflected — 'get_package_info.name'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `get_package_info` |
| Parameter | `name` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
Package "<script>alert(1)</script>" not found on npm.
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-003 — Injection reflected — 'get_package_versions.name'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `get_package_versions` |
| Parameter | `name` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
Package "<script>alert(1)</script>" not found on npm.
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-004 — Injection reflected — 'get_download_stats.name'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `get_download_stats` |
| Parameter | `name` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
Package "<script>alert(1)</script>" not found or has no download stats.
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-005 — Injection reflected — 'check_vulnerabilities.name'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `check_vulnerabilities` |
| Parameter | `name` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
Package "<script>alert(1)</script>@test" not found on npm.
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-006 — Injection reflected — 'check_vulnerabilities.version'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `check_vulnerabilities` |
| Parameter | `version` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
Package "test@<script>alert(1)</script>" not found on npm.
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-007 — Injection reflected — 'compare_packages.package1'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `compare_packages` |
| Parameter | `package1` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
## Package Comparison

❌ <script>alert(1)</script> not found

────────────────────────────────────────

**test** v3.3.0
  License: MIT
  Downloads/month: 269.556
  Dependencies: 3
  Last published: 8/2/2023
  Quality: 85%  Maintenance: 100%  Popularity: 15%
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-008 — Injection reflected — 'compare_packages.package2'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `compare_packages` |
| Parameter | `package2` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
## Package Comparison

**test** v3.3.0
  License: MIT
  Downloads/month: 269.556
  Dependencies: 3
  Last published: 8/2/2023
  Quality: 85%  Maintenance: 100%  Popularity: 15%

────────────────────────────────────────

❌ <script>alert(1)</script> not found
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-009 — Injection reflected — 'get_changelog.name'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `get_changelog` |
| Parameter | `name` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
Package "<script>alert(1)</script>" not found on npm.
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-010 — Injection reflected — 'get_changelog.from_version'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `get_changelog` |
| Parameter | `from_version` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
Changelog for **test** after v<script>alert(1)</script>:

### v3.3.0 — 8/2/2023
## [3.3.0](https://github.com/nodejs/node-core-test/compare/v3.2.1...v3.3.0) (2023-02-08)


### Features

* add --test-name-pattern CLI flag ([c5fd64c](https://github.com/nodejs/node-core-test/commit/c5fd64cc2e2e22b35fd6
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-011 — Injection reflected — 'get_changelog.to_version'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `get_changelog` |
| Parameter | `to_version` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
No releases found for **test** up to v<script>alert(1)</script>.
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-012 — Injection reflected — 'get_dependents.name'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `get_dependents` |
| Parameter | `name` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
Package "<script>alert(1)</script>" not found on npm.
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-013 — Injection reflected — 'get_package_readme.name'

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | MCP05 |
| Tool | `get_package_readme` |
| Parameter | `name` |
| Confidence | 30% |

Payload was echoed back as a named JSON field — likely input logging, not a vulnerability (field: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
Package "<script>alert(1)</script>" not found on npm.
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-014 — Injection reflected — 'get_package_readme.version'

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP05 |
| Tool | `get_package_readme` |
| Parameter | `version` |
| Confidence | 85% |

Payload was reflected verbatim in the response without sanitization (field classification: generic_string).


**Payload:**
```
<script>alert(1)</script>
```


**Evidence:**
```
Version "<script>alert(1)</script>" not found for "test".
```


**Remediation:** Sanitize and validate all input parameters. Never pass raw user input to shell commands, file paths, or SQL queries.

---

### CORVUS-015 — 'search_packages' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `search_packages` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-016 — 'get_package_info' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_package_info` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-017 — 'get_package_versions' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_package_versions` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-018 — 'get_download_stats' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_download_stats` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-019 — 'check_vulnerabilities' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `check_vulnerabilities` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-020 — 'compare_packages' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `compare_packages` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-021 — 'get_changelog' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_changelog` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-022 — 'get_dependents' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_dependents` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-023 — 'get_package_readme' accepts undeclared extra fields

| Field | Value |
|-------|-------|
| Severity | **LOW** |
| OWASP | EXT01 |
| Tool | `get_package_readme` |
| Parameter | `—` |
| Confidence | 80% |

Tool accepted arguments containing '__proto__' without error.




**Remediation:** Reject calls containing parameters not declared in inputSchema.

---

### CORVUS-024 — Response Flooding — 'get_package_readme' returns oversized response

| Field | Value |
|-------|-------|
| Severity | **HIGH** |
| OWASP | MCP10 |
| Tool | `get_package_readme` |
| Parameter | `—` |
| Confidence | 85% |

Tool 'get_package_readme' returned 12,112 bytes (threshold: 8,192 bytes). Large responses can overflow LLM context windows, push out system prompts, or cause denial-of-service in agent pipelines.



**Evidence:**
```
12,112 bytes — preview: # test@3.3.0
📦 https://www.npmjs.com/package/test

---

# The `test` npm package

[![CI](https://github.com/nodejs/node-core-test/actions/workflows/ci.yml/badge.svg)](https://github.com/nodejs/node-co
```


**Remediation:** Paginate or cap tool responses. Never return unbounded data. Aim for responses under 4 KB to preserve LLM context budget.

---

### CORVUS-025 — Response Flooding — 'get_package_readme' returns highly repetitive content

| Field | Value |
|-------|-------|
| Severity | **MEDIUM** |
| OWASP | MCP10 |
| Tool | `get_package_readme` |
| Parameter | `—` |
| Confidence | 80% |

Tool 'get_package_readme' response contains a phrase repeated ≥15 times. Repetitive content can be used to anchor specific instructions into LLM memory or exhaust context budget with low-information noise.



**Evidence:**
```
# test@3.3.0
📦 https://www.npmjs.com/package/test

---

# The `test` npm package

[![CI](https://github.com/nodejs/node-core-test/actions/workflows/ci.yml/badge.svg)](https://github.com/nodejs/node-core-test/actions/workflows/ci.yml)

This is a user-land port of [`node:test`](https://nodejs.org/api/
```


**Remediation:** Deduplicate response data. Avoid returning the same value or phrase more than a handful of times in a single response.

---

### CORVUS-026 — initialize accepts protocol version downgrade

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

### CORVUS-027 — Null request ID accepted — JSON-RPC spec violation

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

### CORVUS-028 — Protocol crash — string params caused server disconnect

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

### CORVUS-029 — MCP server exposes tools with completable arguments

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
# CS06 — Curated Findings
**Scan date:** 2026-07-05 · **Corvus v1.1.0** · **26 targets (13 npm + 13 uvx)**

## Scan Stats

| Metric | Value |
|--------|-------|
| Targets | 26 |
| OK (with findings) | 12 |
| ERROR (startup fail) | 14 (54%) |
| Raw findings | 127 |
| Estimated TPs | ~52 |
| Estimated FPs | ~75 |
| FP rate | ~59% (driven by fdic: 35 FPs from long descriptions) |
| Without fdic outlier | ~46% |

**ERROR servers (14):** tiny-stdio, socketsecurity, grayboard, axiom, sap-mdk (npm);
terraform-aws, sns-sqs, nova-canvas, cdk-aws, cost-analysis, lambda-aws, git-repo-research, code-doc-gen (AWS Labs uvx); redis (uvx)

---

## Notable Findings

### CS06-F01 — CRITICAL: Anti-Forensic Log Erasure in Game Engine MCP
**Target:** godot-mcp-server v0.5.0 (262/wk npm) · **Module:** log-audit · **OWASP:** MCP08 · **Confidence:** 90%

`clear_console_log` tool allows erasing the Godot editor console log via MCP. An attacker with access to the MCP session can invoke this tool to destroy evidence of malicious tool invocations.

**Significance:** Anti-forensic capability in a development tool — erasing logs in the same session that performed unauthorized operations (e.g., `save_resource_to_file`, `delete_file`). Combined with CS06-F02/F03, this is a complete exfiltrate-then-cover-tracks chain.

---

### CS06-F02 — HIGH: Unrestricted Write Scope in Game Scene Tool
**Target:** godot-mcp-server · **Module:** scope-audit · **OWASP:** MCP02 · **Confidence:** 85%

`save_resource_to_file` description states it works for "any Resource" and "any Resource currently held by a node", suggesting no restriction on which resources can be saved or where.

---

### CS06-F03 — HIGH: Path Traversal in save_resource_to_file
**Target:** godot-mcp-server · **Module:** scope-audit · **OWASP:** MCP02 · **Confidence:** 65%

`save_resource_to_file(save_to=<path>)` — write-path parameter with no sanitization described. An attacker can supply traversal sequences to write arbitrary `.tres` files outside the project directory.

---

### CS06-F04 — HIGH: Path Traversal in take_screenshot
**Target:** godot-mcp-server · **Module:** scope-audit · **OWASP:** MCP02 · **Confidence:** 65%

`take_screenshot(save_to=<path>)` — saves PNG to caller-supplied path without documented path restriction. Similar traversal vector to CS06-F03.

---

### CS06-F05 — HIGH: XSS Payload Reflected Verbatim in TypeScript Docs MCP
**Target:** functype-mcp-server v1.6.1 (409/wk npm) · **Module:** cmd-injection · **OWASP:** MCP05 · **Confidence:** 85%

`get_type_api(type_name=<script>alert(1)</script>)` returns: `Type "<script>alert(1)</script>" not found.` — verbatim echo in error message. Any HTML-rendering MCP client consuming this response is vulnerable to XSS.

Same issue in `set_functype_version(version=<script>alert(1)</script>)` → `Invalid version "<script>alert(1)</script>"`.

---

### CS06-F06 — HIGH: XSS Reflection in Official AWS Kendra MCP Server
**Target:** awslabs.amazon-kendra-index-mcp-server v1.28.1 (478/wk PyPI) · **Module:** cmd-injection · **OWASP:** MCP05 · **Confidence:** 85%

`KendraQueryTool(region=<script>alert(1)</script>)` returns JSON with `"region": "<script>alert(1)</script>"` unsanitized.
`KendraQueryTool(indexId=<script>alert(1)</script>)` same pattern.

**Significance:** Official AWS Labs server — same response-injection pattern independently confirmed in two different ecosystems (npm + PyPI) in the same scan batch. Systematic issue across MCP SDK implementations.

---

### CS06-F07 — MEDIUM: Tool Chaining — Imperative Cross-Tool Directives (godot, 4 tools)
**Target:** godot-mcp-server · **Module:** tool-chaining · **OWASP:** EXT06 · **Confidence:** 65%

4 tools use imperative language forcing LLM to call specific other tools:
- `modify_node_property`: "use attach_script (NOT modify_node_property with property='script')"
- `set_sprite_texture`: references `get_resource_info` as prerequisite
- `set_node_properties`: "Resource-typed properties must use set_resource_property / set_sprite_texture"
- `connect_signal`: "scripts must be attached via attach_script (NOT via modify_node_property)"

Pattern: tool descriptions that instruct the LLM on which OTHER tools to call can be abused in a multi-server session to covertly chain into privileged tools.

---

### CS06-F08 — HIGH: Empty Tool Surface — Server Starts but Exposes 0 Tools
**Target:** @yjzf/mcp-server-yjzf v0.6.2 (566/wk npm) · **Module:** batch-dos · **OWASP:** EXT01 · **Confidence:** 85%

Server starts, completes initialize handshake, but returns `tools: []`. Also crashes on JSON-RPC batch array. This represents an unusual attack surface: a server that successfully integrates with an MCP client but silently provides no functionality — a potential vector for rug-pull (CS06 registration succeeded, then tool list emptied).

---

## Scan Table (all 12 OK servers)

| Server | Tools | CRIT | HIGH | MED | LOW | INFO | TPs (est.) | Notes |
|--------|-------|------|------|-----|-----|------|------------|-------|
| godot | 65 | 1 | 3 | 9 | 4 | 4 | 12 | Star finding — CRITICAL clear_console_log |
| fdic | 29 | 0 | 1 | 12 | 18 | 9 | 5 | High FP: long descriptions → MCP03 |
| functype | 5 | 0 | 2 | 2 | 6 | 1 | 7 | XSS reflection in error messages |
| kendra | 2 | 0 | 2 | 2 | 8 | 1 | 7 | AWS Labs — XSS reflection same pattern |
| accessflow | ? | 0 | 0 | 3 | 3 | 2 | 4 | Mostly protocol-level |
| hourei | ? | 0 | 0 | 3 | 4 | 1 | 4 | Japanese law API, clean surface |
| bedrock-kb-retrieval | ? | 0 | 0 | 5 | 4 | 1 | 5 | AWS Labs, schema-level issues |
| ollama | 9 | 0 | 1 | 2 | 1 | 1 | 4 | Shadow tool `run` (HIGH) |
| yjzf | 0 | 0 | 1 | 1 | 1 | 0 | 2 | Empty surface + batch crash |
| search-jan | ? | 0 | 0 | 2 | 1 | 2 | 2 | Jan Browser integration, clean |
| mcp-hn | ? | 0 | 0 | 2 | 2 | 1 | 2 | Hacker News, protocol-level only |
| calculator | ? | 0 | 0 | 2 | 2 | 1 | 2 | Calculator, protocol-level only |

**Totals:** 127 raw · ~56 TP (est.) · ~71 FP (est.) · FP rate ~56%

---

## FP Patterns Identified

1. **fdic description length (MCP03)**: 29-tool banking API has legitimately long tool descriptions. ~8 MCP03 findings = FP.
2. **fdic "override" keyword (MCP02)**: "override" in `fdic_peer_group_analysis` refers to overriding a query mode, not privilege escalation. FP.
3. **kendra LOW echo at confidence 30%** (MCP05): echo with named field + confidence 30% correctly flagged as LOW (likely FP). The HIGH at 85% is real.

---

## Categorías Nuevas para Ekoparty Paper

- **Sector gaming/game engine**: godot-mcp-server — MCP como superficie de ataque en herramientas de desarrollo de juegos. Pattern: anti-forensics + path traversal unique to game engine context.
- **Fintech/banking MCP**: fdic-mcp-server — 29 tools sobre FDIC BankFind API pública. Alta surface pero mayormente FPs.
- **Response injection (XSS) sistémico**: 2 servidores independientes (functype npm + AWS Kendra PyPI) reflejan payloads XSS sin sanitizar. Patrón sistemático cross-ecosystem.
- **AWS Labs official servers**: kendra arrancó (2 tools). 8 otros AWS Labs servers → ERROR (necesitan AWS credentials para iniciar). Confirma que los AWS MCP servers necesitan environment setup mínimo.

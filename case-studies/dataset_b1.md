# B1 — Dataset Definitivo CS01+CS02

**RT-CORVUS-V25 / 2026-07-01**

Dataset compilado para CFP Ekoparty 2026 y paper arXiv.
Baseline: Corvus v1.0.1 + FP calibration v5.

---

## 1. Overview del Dataset

| Métrica | CS01 | CS02 | Combined |
|---------|------|------|----------|
| Servers auditados | 22 | 33 | 55 |
| Servers escaneados (done) | 22 | 31 | 53 |
| Servers skip (config/env) | 0 | 18 | 18 |
| Servers sin findings | 1 | ~3 | ~4 |
| Total findings curados | 72 | ~51 | ~123 |
| TRUE POSITIVEs | 53 | ~37 | ~90 |
| FALSE POSITIVEs | 19 | ~14 | ~33 |
| FP rate | 26.4% | ~27.5% | ~26.8% |

---

## 2. Breakdown por Categoría OWASP MCP Top 10

Basado en findings curados (TPs confirmados manualmente post-scan).

| Categoría | TPs CS01 | TPs CS02 | Total TPs | Servers afectados |
|-----------|----------|----------|-----------|------------------|
| MCP01 Token Exposure | 1 | 2 | 3 | 3 |
| MCP02 Scope Creep / SSRF | 7 | 10 | 17 | 11 |
| MCP03 Shadow Tool | 9 | 11 | 20 | 14 |
| MCP04 Supply Chain | 7 | 6 | 13 | 15 |
| MCP05 Injection / Traversal | 17 | 11 | 28 | 16 |
| MCP07 Init Audit | 4 | 4 | 8 | 37* |
| MCP08/MCP10 Response Flood | 5 | 2 | 7 | 7 |
| EXT01 Protocol Crash | 1 | 11 | 12 | 15 |
| EXT03/MCP03 Shadow Tool | (merged above) | | | |
| EXT04 Init Audit | (merged MCP07) | | | |
| EXT05 Resource URI | 0 | 1 | 1 | 1 |
| EXT06 Tool Chaining | 0 | 0 | 0 | 0 |
| EXT07 Response Injection | 0 | 0 | 0 | 0 |

*Protocol downgrade finding: 37/52 servers with init-audit run (71.2%)

---

## 3. Prevalencia por Tipo de Vulnerabilidad

Distribución en los 55 servers del dataset combinado (raw scan data, antes de curation).

| Tipo | Servers afectados | Prevalencia |
|------|------------------|-------------|
| Protocol version downgrade | 37/52 | **71.2%** |
| Shadow tool / arbitrary exec | 24/55 | **43.6%** |
| Injection / path traversal | 16/55 | **29.1%** |
| Protocol crash (DoS) | 15/55 | **27.3%** |
| Supply chain (vuln dep) | 15/55 | **27.3%** |
| Scope creep (input schema) | 11/55 | **20.0%** |
| SSRF (confirmed by timing/content) | 5/55 | **9.1%** |
| Response flood (no pagination) | 7/55 | **12.7%** |
| Token / credential exposure | 3/55 | **5.5%** |

---

## 4. Findings Destacados por Severidad

### CRITICAL (2 TPs)

| ID | Target | Descripción |
|----|--------|-------------|
| CS01-F11 | server-everything | `get-env` expone todas las env vars del proceso incluyendo API keys / tokens |
| CS02-F19 | remnux-mcp-server | `run_tool.command` CRITICAL injection — RCE real en malware analysis server |

### HIGH con mayor impacto de ecosistema

| Patrón | Finding | Impacto |
|--------|---------|---------|
| SDK advisory cascada | CS01-F09/F16/F35, CS02-F09/F10/F31 | ≥6 servers, >200 estimados en ecosistema npm |
| Protocol crash sistémico | CS02-F08 (11 targets) | DoS remoto en 27% de servers testados |
| Protocol downgrade | CS01-F69/F71, CS02 init-audit | 71.2% de servers no validan protocolVersion |
| SSRF en fetch servers | CS01-F14/F66/F68, CS02-F24/F25 | Acceso a metadata cloud (169.254.169.254) confirmado |
| Arbitrary exec shadow | CS01/CS02 múltiples | `execute_command`, `run_tool`, `shell_execute` en 14 servers |

---

## 5. FP Rate Evolution (Histórico)

| Versión | FP rate | Mejora vs anterior | Calibración aplicada |
|---------|---------|--------------------|----------------------|
| v0.8.0 | ~42% | — | baseline |
| v0.9.0 | ~35% | -7pp | v1+v2 (TS annotations, primitivos, union types) |
| v0.9.2 | ~30.6% | -4.4pp | v3 (plain-text echo, template literals, code blocks) |
| v1.0.0 | ~28% | -2.6pp | v4 (scope qualifiers, DB-prefix, transformation tools) |
| v1.0.1 | **26.4%** | -1.6pp | v4b (param_smuggling isError, query-verb tools, OS error traversal) |
| v1.0.1+v5 | **TBD** | expected -3pp | v5 (path param blanket, token_exposure dedup) |

FP rate medido sobre CS01 dataset (22 servers, 72 findings curados, 19 FP).

---

## 6. Stats de init_audit (A3)

Basado en `case-studies/init_audit_stats.py` — 52 servers con init-audit ejecutado.

| Probe | Servers aceptan | Prevalencia |
|-------|----------------|-------------|
| Protocol version downgrade (`1.0`, `2024-01-01`, `""`, `0.1`) | **37/52** | **71.2%** |
| serverInfo injection (control chars) | 0/52 | 0% |

**CFP citation:**
> «37 of 52 audited MCP servers (71%) accepted protocol version downgrade requests,
> indicating systemic lack of protocolVersion validation across the MCP ecosystem.»

---

## 7. Supply Chain — SDK Advisory Cascade

El advisory `@modelcontextprotocol/sdk@<=1.25.1` (HIGH, sin CVE) afecta a todo el ecosistema Node.js MCP.

| Server | CS | Advisory |
|--------|----|----------|
| server-github | CS01 | ✅ F09 |
| npm-search-mcp-server | CS01 | ✅ F16 |
| server-postgres | CS01 | ✅ F35 |
| mcp-server-commands | CS01 | ✅ (batch) |
| database-server-executeautomation | CS01 | ✅ F47 |
| mcp-server-docker | CS02 | ✅ F09 |
| flightradar-mcp-server | CS02 | ✅ F10 |
| mysql-mcp-server | CS02 | ✅ F31 |

**8+ servers confirmados.** Estimado ecosistémico: >200 packages npm que usan el SDK base.

---

## 8. Responsible Disclosure (6 GHSAs)

| GHSA | Target | Severidad | Estado |
|------|--------|-----------|--------|
| GHSA-mf64-cgv4-ppcx | @playwright/mcp | HIGH | MSRC+CVE pending |
| GHSA-7763-c5gf-v5fj | mcp-shell-server | HIGH | Submitted, sin respuesta |
| GHSA-pr6r-h66r-m47j | server-everything | HIGH | Submitted, sin respuesta |
| GHSA-7w27-7xwv-x6x2 | mcp-server-sqlite | HIGH | Submitted, sin respuesta |
| GHSA-43j9-hmpq-cgv7 | remnux-mcp-server | CRITICAL | 90d (2026-06-29) |
| GHSA-qwwj-38wj-ffvw | myclaw-toolkit | HIGH | 90d (2026-06-29) |

Próximo ping: **2026-07-09** (playwright, shell, everything, sqlite — sin respuesta).

---

## 9. Next Steps → B2 CFP Ekoparty

Ángulos del abstract (deadline 2026-08-14):

1. **Protocol crash sistémico** — 27% de servers crashean con method name sobredimensionado (DoS remoto)
2. **Supply chain cascade** — SDK advisory afecta >200 packages estimados; 8 confirmados en dataset
3. **Protocol downgrade** — 71% no validan `protocolVersion` (vector de bypass de seguridad de protocolo)
4. **SSRF/Injection** — 9.1% SSRF confirmado por timing/content, 29% injection surface
5. **FP rate evolution** — reducción sistemática de 42% → 26.4% en 5 iteraciones de calibración
6. **EXT05/EXT06/EXT07** — gaps más allá del OWASP MCP Top 10 original

Script de stats: `case-studies/init_audit_stats.py`

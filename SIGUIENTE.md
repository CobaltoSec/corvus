# SIGUIENTE — Corvus

## Objetivo estratégico: Ekoparty 2026 Buenos Aires (7-9 oct)

Corvus es el framework con más chances de ser aceptado en Ekoparty. El ángulo: **primer scanner open source del OWASP MCP Top 10 — con datos reales**.
CFP abierto en Sessionize (track MainTrack + Red Team Space). **Deadline real: 14 agosto 2026**. Red Team Space 2026 CFP no anunciado aún — históricamente abre julio, cierra ~17 agosto.

Gap crítico a cerrar: **no hay case study completo contra targets reales**. Sin eso no hay charla.

---

## Estado actual (post v0.7.0)

- **v0.7.0** released 2026-06-25: A1-A9 + M1-M3 implementados, 97 tests pasan
- **CS01** en progreso: `case-studies/cs01-mcp-ecosystem/` — 4 servers escaneados (server-filesystem/memory/sequential-thinking/everything), 5 TP / 3 FP documentados
- **PyPI** pendiente: v0.5.0 live pero v0.5.1 y v0.7.0 necesitan upload manual con token
- **kestrel-pub**: push pendiente (v0.7.0 local, tag pendiente)

---

## Bloque siguiente — CS01 Completion (A8 + report final)

### A8 — server-github con GITHUB_TOKEN

```bash
# Setup: token read-only scope repo:read
$env:GITHUB_TOKEN = "ghp_..."
.venv/Scripts/corvus.exe scan `
  --transport stdio `
  --cmd "npx -y @modelcontextprotocol/server-github" `
  --sarif --log-requests
```

Superficie esperada: tool descriptions con repo names embebidos → candidato MCP01 (tool poisoning vía markdown).

### CS01 Batch Scan (A8 + otros Tier A pendientes)

```yaml
# targets-cs01-tier-a.yaml
targets:
  - name: server-github
    transport: stdio
    cmd: ["npx", "-y", "@modelcontextprotocol/server-github"]
  - name: server-sqlite
    transport: stdio
    cmd: ["npx", "-y", "@modelcontextprotocol/server-sqlite", "/tmp/test.db"]
  - name: server-git
    transport: stdio
    cmd: ["npx", "-y", "@modelcontextprotocol/server-git"]
```

```powershell
.venv/Scripts/corvus.exe batch targets-cs01-tier-a.yaml `
  --output-dir case-studies/cs01-mcp-ecosystem/batch-tier-a `
  --min-confidence 60 --sarif
```

### CS01 report final

- Completar `findings-curated.md` con todos los TPs verificados manualmente
- Escribir `report.md` narrativo: methodology + findings + estadísticas (% con poisoning, % con traversal, etc.)
- **Goal:** ≥ 3 HIGH reales para CFP

---

## PyPI upload (pendiente — token manual)

```powershell
cd sectors/red-team/corvus
python -m build
# Sube v0.7.0
.venv/Scripts/twine.exe upload dist/cobaltosec_corvus-0.7.0*
```

---

## Bloque 3 — Calibración post-CS01

Pulir FPs que CS01 exponga en targets reales:

- **info-disclosure calibración** — verificar reflections con patrón isError + JSON echo
- **schema-bypass LOWs genuinos** — remediation hint `ConfigDict(extra='forbid', strict=True)` para pydantic v2
- **param-injection payloads adicionales** — header injection (`\r\nX-Injected:`) y LDAP injection

---

## Bloque 4 — Propuesta Ekoparty (RT-CORVUS-EKO01)

Una vez CS01 tiene ≥3 HIGH reales:

### Abstract propuesto (inglés)

**Título:** "Corvus: Automated OWASP MCP Top 10 Scanning — What We Found in 30 MCP Servers"

**Abstract:** MCP (Model Context Protocol) is the emerging standard for connecting tools to LLMs. In 2025-2026, thousands of MCP servers were deployed with no security review. I built Corvus, the first open-source scanner for the OWASP MCP Top 10. In this talk I present results from auditing 30+ public MCP servers: hidden prompt injection in tool descriptions, unvalidated path traversal, confirmed SQL injection, and tools that mutate their surface mid-session (rug pull). Live demo included.

### Estructura de charla (35 min)

1. **Qué es MCP y por qué importa** (5 min)
2. **OWASP MCP Top 10** (8 min)
3. **Corvus arquitectura** (7 min)
4. **Case Study CS01** (10 min)
5. **Demo en vivo** (5 min)

### Materiales

- [ ] Abstract enviado a Sessionize (track Red Team Space)
- [ ] Bio del speaker (Nicolás Padilla, CobaltoSec)
- [ ] Slides (30 slides máx)
- [ ] Demo environment preparado y testado
- [ ] PyPI v0.7.0 live
- [ ] README actualizado con CS01 findings link

---

## Timeline estimado

| Bloque | Duración | Condición de éxito |
|--------|----------|--------------------|
| A8 + CS01 batch Tier A | 1 sesión | server-github + sqlite + git escaneados |
| CS01 report final | 1 sesión | ≥3 HIGH reales documentados |
| Bloque 3 (calibración) | 1 sesión | FP rate < 10% |
| Bloque 4 (propuesta Ekoparty) | 1 sesión | Abstract + outline listos |
| **Postulación** | — | CFP enviado antes de cierre **14 agosto 2026** |

---

## Qué NO hacer antes de Ekoparty

- No rediseñar el core — v0.7.0 está bien como está
- No agregar módulos nuevos sin case study que los motive
- No publicar findings críticos sin responsible disclosure a los maintainers

# Mini prompt — Disclosure Batch 2 (2026-07-02)

Pegar este contexto al inicio de la sesión de disclosure.

---

## Contexto

Soy Nico Padilla (CobaltoSec, @nicoPadi1002). Trabajo en Corvus, un framework de security testing para MCP servers.  
Tengo 3 GHSAs pendientes de publicar, producto del re-scan CS01 con Corvus v1.0.1 (2026-07-02).  
El proceso de disclosure está documentado en `case-studies/DISCLOSURE-PROCESS.md` dentro del repo Corvus (`C:\Proyectos\CobaltoSec\sectors\red-team\corvus`).

**Repo de advisories:** `CobaltoSec/advisories`  
**Token necesario:** `repo` + `security_events` scopes. Configurar con `$env:GITHUB_TOKEN = "ghp_..."` antes de empezar.  
**Sin solicitud de CVE** — publicar directo, sin request.

---

## Tarea

Publicar 3 GHSAs vía API siguiendo el proceso documentado:

### 1. NUEVO — mcp-server-git (F86 + F87) — HIGH

**Package:** `mcp-server-git` (ecosystem: other)  
**Repo:** https://github.com/modelcontextprotocol/servers/tree/main/src/git  
**Maintainer:** @olaservo  
**Vulnerable:** todas las versiones conocidas (no hay releases versionados — main branch)  

**Finding F86:** JSON-RPC batch array crash — payload totalmente válido según spec JSON-RPC 2.0 §6 (array de request objects), el server no lo maneja y desconecta el transporte. DoS reproducible, sin GHSA previo.  
**Finding F87:** Oversized method name → transport failure. Method name >1000 chars provoca desconexión.  

**CWE:** CWE-755 (Improper Handling of Exceptional Conditions)  
**Severity:** high  

**Summary sugerido:** `mcp-server-git crashes on spec-compliant JSON-RPC batch requests and oversized method names`

---

### 2. NUEVO — @modelcontextprotocol/server-sequential-thinking (F90) — MEDIUM

**Package:** `@modelcontextprotocol/server-sequential-thinking` (ecosystem: npm)  
**Repo:** https://github.com/modelcontextprotocol/servers  
**Maintainer:** @olaservo  
**Vulnerable:** `<= 0.6.2` (última versión al momento del scan)  

**Finding F90:** Oversized method name → transport failure. Method name >1000 chars provoca desconexión del transporte stdio. Server oficial del paquete @modelcontextprotocol.  

**CWE:** CWE-400 (Uncontrolled Resource Consumption)  
**Severity:** medium  

**Summary sugerido:** `@modelcontextprotocol/server-sequential-thinking crashes on oversized JSON-RPC method names`

---

### 3. UPDATE — mcp-shell-server (F89) — agregar a GHSA-7763-c5gf-v5fj existente

**GHSA existente:** GHSA-7763-c5gf-v5fj  
**Acción:** PATCH para agregar finding F89 a la descripción existente.  

**Finding F89:** Proto crash adicional — oversized method name → transport failure. Mismo vector que F86/F90 pero en mcp-shell-server. Agrega superficie de ataque al finding de command injection ya documentado.  

**Acción concreta:** Leer descripción actual del GHSA → append sección "## Additional Finding (F89 — Protocol Crash)" → PATCH.

---

## Orden de ejecución

1. Crear GHSA mcp-server-git → invitar @olaservo → publicar
2. Crear GHSA server-sequential-thinking → invitar @olaservo → publicar  
3. PATCH GHSA-7763-c5gf-v5fj con F89

Verificar cada uno con `gh api repos/CobaltoSec/advisories/security-advisories/{ghsa} | ConvertFrom-Json | Select-Object ghsa_id, severity, state, published_at`

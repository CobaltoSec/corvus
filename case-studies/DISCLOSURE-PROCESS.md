# Corvus — Proceso de Disclosure Responsable

**Repo de advisories:** `CobaltoSec/advisories`  
**URL:** https://github.com/CobaltoSec/advisories/security/advisories  
**Sin solicitud de CVE** — el GHSA ID es suficiente para el portfolio. CVE solo si el maintainer lo solicita desde su repo oficial.

---

## Draft vs Publicar directo

| Condición | Acción |
|-----------|--------|
| DoS/crash, sin patch, sin RCE chain | Publicar directo |
| RCE / CRITICAL / auth bypass | Draft → invitar maintainer → esperar 30d → publicar |
| HIGH con exploit chain realista | Draft → invitar maintainer → esperar 30d → publicar |
| Maintainer no responde después de 30d | Publicar |
| CVE o MSRC pendiente | Mantener draft hasta asignación |
| Maintainer responde y pide tiempo | Respetar hasta máx 90d desde reporte |

**Regla general:** si el finding puede usarse para comprometer producción sin intervención del usuario → draft primero. Si es DoS o requiere acceso previo → publicar directo.

---

## Requisitos

Token GitHub (PAT clásico) con scopes: **`repo`** + **`notifications`** + **`write:discussion`**  
(`security_events` queda incluido como sub-scope de `repo`)

```bash
gh api user --include 2>&1 | grep X-Oauth-Scopes
# Esperado: notifications, repo, write:discussion
```

### Límites de la API

| Acción | Posible via API |
|--------|----------------|
| Crear / actualizar / publicar GHSA | ✅ |
| Listar advisories + estado | ✅ |
| Invitar collaborator via `PATCH collaborating_users` | ✅ funciona cross-repo |
| Invitar collaborator via `PUT /collaborators` | ❌ 404 siempre — endpoint incorrecto |
| Comentar en un advisory | ❌ No existe endpoint REST |
| Detectar respuestas de maintainers via API | ❌ Advisory comments no generan notificaciones |

**Seguimiento de respuestas:** manual. Revisar advisory en GitHub web o esperar email. No automatizable.

---

## Flujo completo: GHSA nuevo (bash, copy-paste)

```bash
GHSA_REPO="CobaltoSec/advisories"
MAINTAINER="github-username"   # top contributor del repo target
PKG_NAME="npm-package-name"
PKG_VERSION="<= x.y.z"

# 1. Crear advisory draft
GHSA_ID=$(echo '{
  "summary": "...",
  "description": "...",
  "severity": "high",
  "cwe_ids": ["CWE-77"],
  "vulnerabilities": [{
    "package": {"ecosystem": "npm", "name": "'"$PKG_NAME"'"},
    "vulnerable_version_range": "'"$PKG_VERSION"'",
    "patched_versions": null,
    "vulnerable_functions": []
  }]
}' | gh api repos/$GHSA_REPO/security-advisories -X POST \
     -H "Content-Type: application/json" --input - \
     --jq '.ghsa_id')
echo "Creado: $GHSA_ID"

# 2. Invitar maintainer como colaborador
# IMPORTANTE: usar PATCH con collaborating_users — NO PUT /collaborators (404 siempre)
echo "{\"collaborating_users\": [\"$MAINTAINER\"]}" | \
  gh api repos/$GHSA_REPO/security-advisories/$GHSA_ID \
  -X PATCH -H "Content-Type: application/json" --input - \
  --jq '.collaborating_users[].login'

# 3. Verificar
gh api repos/$GHSA_REPO/security-advisories/$GHSA_ID \
  --jq '{ghsa: .ghsa_id, state: .state, severity: .severity, collaborators: [.collaborating_users[].login]}'
```

---

## Proceso: actualizar GHSA existente

```bash
GHSA="GHSA-xxxx-xxxx-xxxx"

echo '{
  "description": "... descripción actualizada ...",
  "severity": "critical",
  "cwe_ids": ["CWE-918", "CWE-22"]
}' | gh api repos/CobaltoSec/advisories/security-advisories/$GHSA \
     -X PATCH -H "Content-Type: application/json" --input -
```

## Proceso: publicar GHSA

```bash
GHSA="GHSA-xxxx-xxxx-xxxx"

echo '{"state": "published"}' | \
  gh api repos/CobaltoSec/advisories/security-advisories/$GHSA \
  -X PATCH -H "Content-Type: application/json" --input -
```

---

## Tabla CWE por tipo de finding

| Finding type          | CWE      | Descripción                                      |
|-----------------------|----------|--------------------------------------------------|
| DoS / crash           | CWE-400  | Uncontrolled Resource Consumption                |
| Protocol crash        | CWE-755  | Improper Handling of Exceptional Conditions      |
| Command injection     | CWE-78   | OS Command Injection                             |
| LFI / path traversal  | CWE-22   | Path Traversal                                   |
| SSRF                  | CWE-918  | Server-Side Request Forgery                      |
| Auth bypass HTTP      | CWE-306  | Missing Authentication for Critical Function     |
| Token exposure        | CWE-522  | Insufficiently Protected Credentials             |
| Prompt/query injection| CWE-77   | Injection (prompt/query context)                 |
| Supply chain          | CWE-1395 | Dependency on Vulnerable Third-Party Component   |
| Shadow tool           | CWE-345  | Insufficient Verification of Data Authenticity   |

## Tabla severity por finding

| Corvus severity | GHSA severity |
|-----------------|---------------|
| CRITICAL        | critical      |
| HIGH            | high          |
| MEDIUM          | medium        |
| LOW             | low           |

---

## Maintainers conocidos

| Repo / Package                              | Maintainer GitHub   | Invitado | PVR |
|---------------------------------------------|---------------------|----------|-----|
| modelcontextprotocol/servers                | olaservo            | ✅       | No  |
| modelcontextprotocol/mcp-server-sqlite      | olaservo            | ✅       | No  |
| nicholasgasior/mcp-shell-server             | nicholasgasior (mako10k) | ✅  | No  |
| REMnux/remnux-mcp-server                    | lennyzeltser        | N/A (published) | No |
| microsoft/playwright                        | pavelfeldman        | ✅       | No  |
| Dusheh/myclaw-toolkit                       | Dusheh              | ✅       | No  |
| KyrieTangSheng/mcp-server-nationalparks     | KyrieTangSheng      | ✅       | No  |
| cyanheads/pubmed-mcp-server                 | cyanheads           | ✅       | No  |
| idachev/mcp-javadc                          | idachev             | ✅       | No  |
| nrwl/nx-console (nx-mcp)                    | vsavkin             | ✅       | No  |
| Jpisnice/shadcn-ui-mcp-server               | Jpisnice            | ✅       | No  |
| Hack23/European-Parliament-MCP-Server       | pethers             | ✅       | No  |
| GET-Technology-Inc/jamf-docs-mcp-server     | h1431532403240      | ✅       | No  |
| makenotion/notion-mcp-server                | mquan               | ✅       | No  |
| benborla/mcp-server-mysql                   | benborla            | ✅       | No  |

**Cómo encontrar maintainer:** `npm show <package> repository.url` → extrae el GitHub username del repo.

PVR = Private Vulnerability Reporting. Todos los targets conocidos lo tienen deshabilitado → siempre usar `CobaltoSec/advisories` + invitar via `collaborating_users`.

---

## Errores comunes — no repetir

| Error | Por qué falla | Correcto |
|-------|--------------|----------|
| `PUT /security-advisories/{ghsa}/collaborators` | 404 siempre en repos distintos al del package | `PATCH /security-advisories/{ghsa}` con `collaborating_users` |
| Usar Shrike (`shrike_disclose_github`) para GHSAs de Corvus | Shrike es para huntr/0din/google_vrp — GHSAs de Corvus van via `gh api` directo | `gh api` como en el flujo completo de arriba |
| Crear GHSA sin invitar collaborador en el mismo paso | Quedan huérfanos sin notificación al maintainer | Crear + invitar como bloque único (ver flujo completo) |

---

## GHSAs activos (2026-07-02)

| GHSA                  | Package                              | Severity    | Collaborator    | Estado             | Publicar    |
|-----------------------|--------------------------------------|-------------|-----------------|-------------------|-------------|
| GHSA-mf64-cgv4-ppcx   | @playwright/mcp                      | HIGH        | pavelfeldman ✅  | draft, 90d        | 2026-09-25  |
| GHSA-7763-c5gf-v5fj   | mcp-shell-server                     | HIGH        | mako10k ✅       | draft             | 2026-07-25  |
| GHSA-pr6r-h66r-m47j   | @modelcontextprotocol/server-everything | HIGH     | olaservo ✅      | draft             | 2026-07-25  |
| GHSA-7w27-7xwv-x6x2   | mcp-server-sqlite                    | HIGH        | olaservo ✅      | draft             | 2026-07-25  |
| GHSA-43j9-hmpq-cgv7   | remnux-mcp-server                    | MEDIUM      | N/A             | **published** ✅   | —           |
| GHSA-qwwj-38wj-ffvw   | myclaw-toolkit                       | **CRITICAL**| Dusheh ✅        | draft (LFI+SSRF)  | 2026-07-29  |
| GHSA-hv3x-m9fv-4vhf   | mcp-server-git                       | HIGH        | N/A             | **published** ✅   | —           |
| GHSA-3f55-qgq4-f88c   | server-sequential-thinking           | MEDIUM      | N/A             | **published** ✅   | —           |
| GHSA-rqqc-2cx5-vp44   | mcp-server-nationalparks             | HIGH        | KyrieTangSheng ✅| draft            | 2026-08-01  |
| GHSA-m2x9-5c27-vvc3   | @cyanheads/pubmed-mcp-server         | HIGH        | cyanheads ✅     | draft            | 2026-08-01  |
| GHSA-m6h2-xr6q-9m7p   | @idachev/mcp-javadc                  | HIGH        | idachev ✅       | draft            | 2026-08-01  |
| GHSA-m9p4-rqc7-2fqx   | nx-mcp                               | HIGH        | vsavkin ✅       | draft            | 2026-08-01  |
| GHSA-q974-p8xv-f7c7   | @jpisnice/shadcn-ui-mcp-server       | HIGH        | Jpisnice ✅      | draft            | 2026-08-01  |
| GHSA-qc46-wfh2-238g   | european-parliament-mcp-server       | HIGH        | pethers ✅       | draft            | 2026-08-01  |
| GHSA-rqqv-9rxr-gj2h   | @get-technology-inc/jamf-docs-mcp-server | HIGH    | h1431532403240 ✅| draft            | 2026-08-01  |
| GHSA-gpm5-mj27-94gp   | @notionhq/notion-mcp-server          | HIGH        | mquan ✅         | draft            | 2026-08-01  |
| GHSA-6j6r-pf9m-gqxf   | @benborla29/mcp-server-mysql         | MEDIUM      | benborla ✅      | draft            | 2026-08-01  |
| GHSA-vrmg-6pw3-qwfg   | @sap-ux/fiori-mcp-server             | HIGH        | IainSAP + mikicvi-SAP ✅ | draft CS03  | 2026-10-03  |
| GHSA-frqj-945w-4qp2   | markitdown-mcp                       | HIGH        | afourney ✅              | draft CS03  | 2026-10-03  |
| GHSA-8ggf-fm7g-7pxf   | @upstash/context7-mcp                | MEDIUM      | enesgules + fahreddinozcan ✅ | draft CS03 | 2026-10-03  |
| GHSA-4r48-4m95-6rm8   | @heroku/mcp-server                   | HIGH        | justinwilaby + sbosio ✅     | draft CS03 | 2026-10-03  |
| GHSA-2g9w-p2x3-97pp   | mcp-devutils                         | **CRITICAL**| hlteoh37 ✅                  | draft CS04 | 2026-08-03  |
| GHSA-w5c8-hjv7-p95r   | @aryanbv/pdf-toolkit-mcp             | MEDIUM      | AryanBV ✅                   | draft CS04 | 2026-08-03  |

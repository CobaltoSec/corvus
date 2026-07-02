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

Token GitHub con scopes `repo` + `security_events`.

```powershell
$env:GITHUB_TOKEN = "ghp_..."
gh auth status  # verificar: Token scopes: 'repo', 'security_events'
```

---

## Proceso: GHSA nuevo

### 1. Crear el advisory (draft)

```powershell
$body = @{
  summary       = "..."        # < 80 chars, descriptivo
  description   = "..."        # markdown: Finding / PoC / Fix / Notes
  severity      = "critical|high|medium|low"
  cwe_ids       = @("CWE-400") # ver tabla abajo
  vulnerabilities = @(
    @{
      package = @{ ecosystem = "npm|pypi|other"; name = "package-name" }
      vulnerable_version_range = "<= x.y.z"
      patched_versions         = $null   # null hasta que haya fix
      vulnerable_functions     = @()
    }
  )
} | ConvertTo-Json -Depth 5

$tmp = [System.IO.Path]::GetTempFileName()
$body | Out-File $tmp -Encoding utf8
gh api repos/CobaltoSec/advisories/security-advisories -X POST -H "Content-Type: application/json" --input $tmp
Remove-Item $tmp
```

### 2. Invitar al maintainer como colaborador (solo en draft)

> **Nota:** el invite solo funciona mientras el advisory está en `draft`. Una vez publicado, devuelve 404.
> Para advisories cross-repo (paquete en repo ajeno a `CobaltoSec/advisories`) el invite también devuelve 404 — es comportamiento esperado. El advisory publicado es visible públicamente para cualquier maintainer.

```powershell
$ghsa = "GHSA-xxxx-xxxx-xxxx"
$collaborator = @{ login = "username" } | ConvertTo-Json
$tmp = [System.IO.Path]::GetTempFileName()
$collaborator | Out-File $tmp -Encoding utf8
gh api repos/CobaltoSec/advisories/security-advisories/$ghsa/collaborators -X PUT -H "Content-Type: application/json" --input $tmp
Remove-Item $tmp
```

### 3. Publicar

```powershell
$body = @{ state = "published" } | ConvertTo-Json
$tmp = [System.IO.Path]::GetTempFileName()
$body | Out-File $tmp -Encoding utf8
gh api repos/CobaltoSec/advisories/security-advisories/$ghsa -X PATCH -H "Content-Type: application/json" --input $tmp
Remove-Item $tmp
```

### 4. Verificar

```powershell
gh api repos/CobaltoSec/advisories/security-advisories/$ghsa |
  ConvertFrom-Json |
  Select-Object ghsa_id, severity, summary, state, published_at
```

---

## Proceso: actualizar GHSA existente

```powershell
$ghsa = "GHSA-xxxx-xxxx-xxxx"
$body = @{
  description = "... descripción actualizada ..."
  severity    = "medium"
} | ConvertTo-Json

$tmp = [System.IO.Path]::GetTempFileName()
$body | Out-File $tmp -Encoding utf8
gh api repos/CobaltoSec/advisories/security-advisories/$ghsa -X PATCH -H "Content-Type: application/json" --input $tmp
Remove-Item $tmp
```

---

## Tabla CWE por tipo de finding

| Finding type          | CWE      | Descripción                                      |
|-----------------------|----------|--------------------------------------------------|
| DoS / crash           | CWE-400  | Uncontrolled Resource Consumption                |
| Protocol crash        | CWE-755  | Improper Handling of Exceptional Conditions      |
| Command injection     | CWE-78   | OS Command Injection                             |
| SSRF                  | CWE-918  | Server-Side Request Forgery                      |
| Auth bypass HTTP      | CWE-306  | Missing Authentication for Critical Function     |
| Token exposure        | CWE-522  | Insufficiently Protected Credentials             |
| Prompt injection      | CWE-77   | Command Injection (prompt context)               |
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

| Repo / Package                              | Maintainer GitHub   | PVR habilitado |
|---------------------------------------------|---------------------|----------------|
| modelcontextprotocol/servers                | olaservo            | No             |
| modelcontextprotocol/mcp-server-sqlite      | olaservo            | No             |
| nicholasgasior/mcp-shell-server             | nicholasgasior      | No             |
| REMnux/remnux-mcp-server                    | lennyzeltser        | No             |

PVR = Private Vulnerability Reporting. Si está deshabilitado → crear en CobaltoSec/advisories + invitar maintainer.

---

## GHSAs activos (2026-07-02)

| GHSA                  | Package                              | Severity | Estado          | Disclosure date |
|-----------------------|--------------------------------------|----------|-----------------|-----------------|
| GHSA-mf64-cgv4-ppcx   | @playwright/mcp                      | HIGH     | draft, 90d      | 2026-06-25      |
| GHSA-7763-c5gf-v5fj   | mcp-shell-server                     | HIGH     | draft (+F89)    | pendiente       |
| GHSA-pr6r-h66r-m47j   | @modelcontextprotocol/server-everything | MEDIUM | draft           | pendiente       |
| GHSA-7w27-7xwv-x6x2   | mcp-server-sqlite                    | HIGH     | draft           | pendiente       |
| GHSA-43j9-hmpq-cgv7   | remnux-mcp-server                    | MEDIUM   | **published** ✅ | 2026-07-02      |
| GHSA-qwwj-38wj-ffvw   | myclaw-toolkit                       | HIGH     | draft           | pendiente       |
| GHSA-hv3x-m9fv-4vhf   | mcp-server-git                       | HIGH     | **published** ✅ | 2026-07-02      |
| GHSA-3f55-qgq4-f88c   | @modelcontextprotocol/server-sequential-thinking | MEDIUM | **published** ✅ | 2026-07-02 |

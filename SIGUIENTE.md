# SIGUIENTE — Corvus

## Pendiente inmediato — push + PyPI v0.5.1

**Estado:** 4 commits en main local (7b1cc3d → cf96c28), tag v0.5.1 creado localmente.
**64/64 tests pasan.**

### Acciones manuales requeridas

```powershell
cd sectors/red-team/corvus

# 1. Push commits + tag
git push origin main
git push origin v0.5.1

# 2. PyPI (token manual)
.venv/Scripts/twine.exe upload dist/cobaltosec_corvus-0.5.1*

# 3. GitHub release
gh release create v0.5.1 `
  --title "v0.5.1 — FP fixes for pydantic v2 + JSON-echo reflection" `
  --notes "Fixes false positives in schema-bypass (MCP05) and param-injection (MCP02)."
```

### Qué tiene v0.5.1

- **MCP05 schema-bypass**: `_accepted()` chequea `isError:true` → elimina ~10 MEDIUM FPs por tool en kestrel/llamascope
- **MCP02 param-injection FP1**: skip en error responses (`isError:true`) → elimina HIGHs FP de errores de validación
- **MCP02 param-injection FP2**: reflections como JSON key-value echo → downgrade de HIGH a LOW (`_is_json_key_echo`)
- README: sección CLI Reference completa
- 5 tests unitarios nuevos (64 total)
- sdist disponible en `dist/cobaltosec_corvus-0.5.1.tar.gz`

### Resultados E2E llamascope-mcp (v0.5.1)

| Módulo | v0.5.0 | v0.5.1 | Δ |
|--------|--------|--------|---|
| schema-bypass | 10 MEDIUM + 17 LOW | 0 MEDIUM + 10 LOW | -10 MEDIUM |
| param-injection | 6 HIGH | 0 HIGH + 3 LOW (estimado) | -6 HIGH, +3 LOW |

### Próximos (post-v0.5.1)

- **RT-CORVUS-V08** — scan contra kestrel-mcp (74 tools) con v0.5.1 y documentar findings reales
- **info-disclosure calibración** — verificar si reflections de `info-disclosure` tienen el mismo patrón (isError + JSON echo)
- **Schema bypass Tests 2+3** — LOWs genuinos de pydantic v2: agregar remediation hint "use `ConfigDict(extra='forbid', strict=True)`"

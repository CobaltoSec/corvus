# CS01 — Metodología

## Scope

Servidores MCP públicos de uso real: tier A (oficiales @modelcontextprotocol), tier B (community ≥100 stars), tier C (Smithery.ai).

No incluye: servidores privados, servidores que requieren credenciales de producción, servidores de pago sin tier gratuito.

## Proceso por target

```bash
# 1. Scan estático (sin side effects, seguro)
corvus scan --transport stdio --cmd "<cmd>" --module static --sarif --output findings-raw/<target>-static.json

# 2. Scan dinámico completo
corvus scan --transport stdio --cmd "<cmd>" --sarif --output findings-raw/<target>-full.json

# 3. Revisión manual de findings HIGH/CRITICAL
#    - Verificar que no sea FP
#    - Documentar evidencia (snippet del finding)
#    - Agregar a findings-curated.md
```

## Criterio de confirmación

Un finding se considera **confirmado** cuando:
1. El módulo lo reporta HIGH o CRITICAL
2. La revisión manual del payload + response muestra que el servidor realmente procesó el payload malicioso (no solo lo echó sin efecto)
3. Hay evidencia reproducible (snippet en findings-raw/)

## Disclosure

Si se encuentra un finding CRITICAL en un servidor oficial:
1. Documentar internamente primero
2. Notificar al maintainer vía GitHub issue (responsible disclosure, 90 días)
3. Incluir en charla solo si está parchado o el maintainer da OK público

## Herramienta

Corvus — install with `pip install cobaltosec-corvus`.

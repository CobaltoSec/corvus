# Corvus Batch Scan Summary

| Target | CRITICAL | HIGH | MEDIUM | LOW | INFO | Total |
|--------|----------|------|--------|-----|------|-------|
| server-github | 0 | 2 | 0 | 0 | 0 | 2 |
| server-pdf | SKIP | — | — | — | — | — |
| server-everything | 0 | 1 | 2 | 6 | 4 | 13 |

## Notas

### server-pdf — HTTP server, no stdio

`@modelcontextprotocol/server-pdf` es un servidor HTTP (SSE/Streamable HTTP) que bindea en `:3001` por defecto.
No es compatible con lanzamiento automático stdio en batch mode.

**Root cause del ERROR original:** target configurado como `transport: stdio`, pero el server intenta bindear `:3001` al iniciarse como subprocess — falla con `EADDRINUSE` si el puerto está ocupado (conflicto con JuiceShop en lab env).

**Corrección aplicada (v0.8.0):** target actualizado a `transport: http, url: http://localhost:3001/mcp`.

**Para escanear manualmente:**
```bash
# 1. Asegurar que :3001 esté libre
# 2. Iniciar el server en background
npx -y @modelcontextprotocol/server-pdf &
# 3. Correr batch o scan directo
corvus scan --target http://localhost:3001/mcp --transport http
```
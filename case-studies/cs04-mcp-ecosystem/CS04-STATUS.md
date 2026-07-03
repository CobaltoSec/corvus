# CS04 — Estado Dataset (2026-07-03)

## Resumen ejecutivo

| Métrica | Valor |
|---------|-------|
| Servidores escaneados OK | **47** |
| Servidores únicos nuevos | **44** (47 - 3 duplicados de CS01/CS02) |
| Servidores con ERROR | 73 (batches A/B/C con auth requerida) |
| Raw findings CS04 | **979** |
| Curación completada | ✅ 47 IDs asignados (CS04-F01–F47) · FP rate ~44% · 2 GHSAs filed |
| Total acumulado (CS01-CS04) | 101 unique servers, ~1288 raw findings |

---

## Todos los servidores OK — ranked por findings

> Tabla completa de los 47 servidores exitosos. Los 3 marcados con `[DUP]` ya estaban en CS01/CS02 — rescaneados con v1.0.1, findings nuevos posibles.

| Rank | Server | C | H | M | L | I | Total | Prioridad curación |
|------|--------|---|---|---|---|---|-------|--------------------|
| 1 | sveltejs-mcp | **195** | 2 | 6 | 5 | 1 | **209** | ALTA — revisar si CRITICAL son FP de tool-poisoning en docs |
| 2 | mcp-devutils | **30** | 8 | 43 | 79 | 8 | **168** | ALTA — 30C probables supply-chain/scope-creep, verificar |
| 3 | devutils-mcp-server | 0 | 2 | 2 | 39 | 6 | **49** | MEDIA — mayoría LOW, revisar 2H |
| 4 | lunar-mcp-server | 0 | **33** | 9 | 35 | 1 | **78** | ALTA — 33H, necesita verificación |
| 5 | multilingual-dictionary-mcp | 0 | **10** | 7 | 36 | 2 | **55** | ALTA — 10H |
| 6 | mcp-npm-registry | 0 | 7 | 3 | 18 | 1 | 29 | MEDIA |
| 7 | pdf-toolkit-mcp | 0 | 1 | **27** | 1 | 1 | **30** | MEDIA — 27M, patrón schema likely |
| 8 | tradingview-mcp | 0 | 2 | 1 | 10 | **14** | 27 | BAJA — muchos INFO |
| 9 | mcp-mathtools | 0 | 0 | 7 | 13 | 2 | 22 | BAJA |
| 10 | synergy-mcp-server | **2** | 2 | 3 | 10 | 4 | 21 | ALTA — 2C únicos (docs system nuevo) |
| 11 | mantine-mcp-server [DUP] | 0 | 2 | 6 | 6 | 3 | 17 | comparar vs CS02 |
| 12 | hn-mcp | 0 | 3 | 5 | 7 | 2 | 17 | MEDIA |
| 13 | pubmed-search-mcp | 0 | 2 | 10 | 2 | 0 | 14 | MEDIA |
| 14 | academic-mcp | 0 | 1 | 5 | 6 | 1 | 13 | BAJA |
| 15 | flowbite-mcp | **1** | 1 | 3 | 6 | 1 | 12 | MEDIA — 1C |
| 16 | shadcn-cli-mcp | 0 | 0 | 3 | 8 | 1 | 12 | BAJA |
| 17 | npm-helper-mcp | 0 | 2 | 1 | 5 | 4 | 12 | BAJA |
| 18 | arxiv-mcp-server-pypi | 0 | 2 | 5 | 2 | 3 | 12 | MEDIA |
| 19 | faker-mcp-server | 0 | 1 | 3 | 3 | 3 | 10 | BAJA |
| 20 | wikipedia-mcp | 0 | 1 | 2 | 6 | 1 | 10 | BAJA |
| 21 | rosetta-mcp-server | 0 | 2 | 1 | 1 | 5 | 9 | BAJA |
| 22 | mcp-server-duckdb | 0 | 1 | 2 | 5 | 1 | 9 | BAJA |
| 23 | excel-mcp-server | 0 | 0 | 5 | 0 | 3 | 8 | BAJA |
| 24 | open-meteo-mcp | 0 | 1 | 2 | 4 | 1 | 8 | BAJA |
| 25 | marketnow-mcp | 0 | 2 | 3 | 2 | 1 | 8 | BAJA |
| 26 | nextjs-docs-mcp | 0 | 1 | 4 | 2 | 1 | 8 | BAJA |
| 27 | taiga-ui-mcp | 0 | 1 | 3 | 2 | 1 | 7 | BAJA |
| 28 | clarvia-mcp-server | 0 | 1 | 3 | 1 | 2 | 7 | BAJA |
| 29 | mcp-web-search | 0 | 0 | 2 | 4 | 1 | 7 | BAJA |
| 30 | ui5-mcp-server | 0 | 2 | 2 | 1 | 1 | 6 | BAJA |
| 31 | npm-search-mcp-server [DUP] | 0 | 1 | 2 | 2 | 1 | 6 | comparar vs CS01 |
| 32 | shadcn-ui-mcp-server [DUP] | 0 | 1 | 2 | 1 | 2 | 6 | comparar vs CS02 |
| 33 | coingecko-mcp-official | 0 | 1 | 3 | 1 | 1 | 6 | BAJA |
| 34 | hackernews-mcp | 0 | 0 | 2 | 3 | 1 | 6 | BAJA |
| 35 | pulsemcp-pulse-fetch | 0 | 1 | 3 | 1 | 1 | 6 | BAJA |
| 36 | pulsemcp-server | 0 | 1 | 2 | 1 | 1 | 5 | BAJA |
| 37 | mcp-hacker-news | 0 | 2 | 1 | 1 | 1 | 5 | BAJA |
| 38 | mcp-finance-frankfurter | 0 | 0 | 2 | 1 | 2 | 5 | BAJA |
| 39 | hero-fe-mcp-server | 0 | 0 | 3 | 1 | 1 | 5 | BAJA |
| 40 | mcp-open-library | 0 | 2 | 1 | 2 | 1 | 6 | BAJA |
| 41 | wikipedia-mcp-pypi | 0 | 1 | 1 | 1 | 1 | 4 | BAJA |
| 42 | cyanheads-git-mcp | 0 | 1 | 2 | 1 | 0 | 4 | BAJA |
| 43 | dangahagan-weather-mcp | 0 | 1 | 1 | 1 | 1 | 4 | BAJA |
| 44 | chakra-ui-mcp | 0 | 0 | 2 | 1 | 1 | 4 | BAJA |
| 45 | eslint-mcp | 0 | 0 | 2 | 1 | 1 | 4 | BAJA |
| 46 | daisyui-mcp-server | 0 | 0 | 2 | 3 | 1 | 6 | BAJA |
| 47 | open-meteo-mcp-server | 0 | 1 | 1 | 1 | 0 | 3 | BAJA |

**Totales CS04:** 228C | 101H | 191M | 326L | 90I = **979 raw**

---

## Guía de curación para el bloque RT-CORVUS-CS04-CURATION

### Proceso

1. Abrir `case-studies/cs04-mcp-ecosystem/<server>/report.md`
2. Revisar cada finding, clasificar TP/FP con razonamiento
3. Actualizar `findings-curated-cs04.md` (crear nuevo, mismo formato que CS01/CS02)
4. Actualizar `public-stats.yaml` con true_positives / false_positives curados
5. Correr `python scripts/update-public.py`

### Referencia: `findings-curated.md` formato

```
| ID | Target | Módulo | Severidad | Título | Confirmado | Notas |
| CS04-F01 | sveltejs-mcp | MCP03 Tool Poisoning | CRITICAL | ... | ✅ TP | ... |
| CS04-F02 | ... | ... | ... | ... | ❌ FP | ... |
```

### Patrones FP conocidos — aplicar primero como filtro rápido

| Patrón | Módulo | Acción |
|--------|--------|--------|
| `sveltejs-mcp` 195 CRITICAL | MCP03 tool-poisoning | Probablemente FP masivos — el server sirve TypeScript defs que incluyen strings con keywords de "injection". Verificar si evidence es código fuente |
| `password_strength` tool | MCP02 scope-creep | LEGÍTIMO — tool para medir fortaleza, no solicita contraseña real. **FP** |
| EXT14 cancellation crash | Todos los servers | **TP universal** — crash en 37 bytes notifications/cancelled. No revisar individualmente |
| Param smuggling → `isError: true` | EXT01 | Validación correcta del server. **FP** |
| SQL docs FP | MCP05 | "SLEEP", "DROP TABLE" en docs sin ejecución real. Verificar evidence |
| `mcp-devutils` 30 CRITICAL | MCP04 supply-chain | Revisar advisories — ¿cuántos son del mismo SDK cascade? |
| `lunar-mcp-server` 33 HIGH | MCP04 / supply-chain | Probablemente supply-chain cascade del SDK. Verificar |

### Orden recomendado

**Primera pasada (alta prioridad — únicos interesantes para el paper):**
1. `sveltejs-mcp` (195C → esperamos muchos FP, documentar el patrón)
2. `mcp-devutils` (30C — potencialmente reales si son supply-chain nuevos)
3. `synergy-mcp-server` (2C — únicos, design system nuevo)
4. `flowbite-mcp` (1C — verificar)
5. `lunar-mcp-server` (33H — supply-chain cascade?)
6. `multilingual-dictionary-mcp` (10H — offline, interesante si son reales)
7. `pdf-toolkit-mcp` (27M — patrón schema?)

**Segunda pasada (análisis estadístico):**
- Revisar los 40 servidores restantes en orden descendente de findings

### Para el CFP paper (Ekoparty deadline 2026-08-14)

Datos que la curación debe generar:
- FP rate CS04 (para comparar con CS01 23.1% / CS02 20.3%)
- Distribución por categoría (docs vs utilities vs APIs)
- Nuevos patrones encontrados que no estaban en CS01/CS02/CS03
- Servidores destacados para inclusión en disclosure pipeline

---

## Archivos de curación a crear

```
case-studies/cs04-mcp-ecosystem/
├── findings-curated-cs04.md     ← CREAR (mismo formato que CS02/findings-curated.md)
└── CS04-STATUS.md               ← ESTE ARCHIVO (actualizar al cerrar bloque)
```

## Servidores ERROR — no necesitan curación

Los 73 directorios ERROR son de batches A/B/C donde los servers requerían
API key, credenciales, o fallaron por timeout. No hay findings que revisar.
Documentados en `targets-cs04-batch-{a,b,c}.yaml` para referencia.

# SIGUIENTE — Corvus

## RT-CORVUS-V06 — PyPI publish + E2E real engagements

**Objetivo:** publicar en PyPI y validar los 10 módulos contra MCP servers reales.

- **PyPI publish** — `twine upload dist/cobaltosec_corvus-0.5.0-py3-none-any.whl` (requiere token de Nico)
- **E2E contra kestrel-mcp** — `corvus scan --transport stdio --cmd "kestrel-mcp" --sarif` — validar que los 10 módulos producen findings correctos/no FPs contra un MCP real
- **E2E contra llamascope-mcp** — `corvus scan --transport http --url "http://localhost:PORT" --config corvus.toml`
- **Refinamiento de módulos dinámicos** — ajustar thresholds/regex basados en resultados reales (posibles FPs en param-injection y schema-bypass)
- **README.md público** — quick start, lista de módulos con descripción, ejemplo de `corvus.toml`, guía de plugin development

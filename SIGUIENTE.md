# SIGUIENTE — Corvus

## RT-CORVUS-V07 — Refinamiento de módulos + source dist PyPI

**Objetivo:** corregir FPs conocidos, mejorar calidad de findings, y completar la publicación PyPI con sdist.

- **Schema bypass FP review** — el módulo MCP05 reporta MEDIUM/LOW en todos los tools que usan pydantic v2 (kestrel, llamascope). Analizar si es un FP real o finding válido; ajustar threshold o agregar whitelist de frameworks conocidos
- **Injection reflection calibración** — revisar si los HIGH de param-injection en kestrel/llamascope son verdaderos positivos o artefactos de mensajes de error legítimos que incluyen el input
- **Source dist** — `python -m build` produce solo wheel; agregar sdist (`cobaltosec_corvus-0.5.0.tar.gz`) y subir con `twine upload dist/*`
- **corvus scan --help en README** — agregar sección de referencia completa de flags con ejemplos reales de los E2E (kestrel, llamascope)
- **GitHub release v0.5.0** — actualizar descripción del release con link a PyPI y resultados E2E

#!/usr/bin/env python3
"""
Sync public-facing docs from case-studies/public-stats.yaml + live GitHub GHSA API.

Usage:
    python scripts/update-public.py [--dry-run]

Updates:
    - README.md                                  (between <!-- CORVUS_xxx_START --> markers)
    - case-studies/public-stats.yaml             (solo los conteos de GHSAs, desde la API)
    - CobaltoSec-Web/data/generated/corvus-stats.json   (solo numeros — NUNCA prosa)

REGLA DE ORO — POR QUE ESTE SCRIPT YA NO ESCRIBE .ts
    Hasta 2026-07-31 este script reescribia data/toolsData.ts y data/projectsData.ts con
    regex. Piso los mismos tres campos TRES veces (commit 04d2efa y dos veces mas el
    mismo dia), y siempre igual: el regex de la descripcion de Corvus solo aceptaba
    comillas simples,

        r"(slug:\\s*'corvus'.*?description:\\s*\\n?\\s*')([^']+)(')"

    pero esa descripcion es un template literal con BACKTICKS (interpola METRICS). Con
    `.*?` + DOTALL el patron seguia buscando hasta el proximo `description: '` — el de
    **llamascope** — y escribia ahi la prosa de Corvus, imprimiendo "toolsData.ts updated"
    como si todo hubiera salido bien.

    La leccion no es "arreglar el regex". Es que un script no puede decidir a que
    herramienta describe un parrafo. Asi que ahora:

        este script escribe NUMEROS en un JSON. La PROSA es editorial y no la toca nadie.

    data/metrics.ts importa ese JSON y todos los componentes de la web interpolan desde
    METRICS. Es el mismo patron que ya usaba CobaltoSec-Web/scripts/sync-tool-stats.mjs,
    cuya cabecera dice "NO importa ni edita data/toolsData.ts (es de otro paquete)".
"""

import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

try:
    import yaml
except ImportError:
    print("pip install pyyaml")
    sys.exit(1)

ROOT = Path(__file__).parent.parent
STATS_FILE = ROOT / "case-studies" / "public-stats.yaml"
README = ROOT / "README.md"

# Unico destino en la web: un JSON generado. Ningun .ts se toca desde aca.
WEB_GENERATED = Path("C:/Proyectos/CobaltoSec-Web/data/generated")
WEB_STATS_JSON = WEB_GENERATED / "corvus-stats.json"

ADVISORY_REPO = "CobaltoSec/advisories"

DRY_RUN = "--dry-run" in sys.argv


def load_stats() -> dict:
    with open(STATS_FILE, encoding="utf-8") as f:
        return yaml.safe_load(f)


def fetch_ghsa_counts() -> dict:
    """
    Conteo real de advisories por estado, desde la API de GitHub.

    Esta funcion ES la fuente de verdad de published/draft/filed. Antes existia
    (`fetch_ghsas_live`) pero su resultado se DESCARTABA: main() solo imprimia el largo
    de la lista y las cifras publicadas salian del yaml escrito a mano. Por eso el sitio
    decia 19 publicadas cuando la API ya devolvia 21.

    `filed` = published + draft. El estado `closed` existe (advisories retiradas) y NO
    cuenta como presentada.

    Si la API falla, SALIMOS CON ERROR. Continuar con cifras viejas en silencio es
    exactamente como se publicaron tres cifras distintas del mismo hecho.
    """
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{ADVISORY_REPO}/security-advisories?per_page=100",
             "--paginate", "--cache", "0", "--jq", ".[] | .state"],
            capture_output=True, text=True, timeout=60,
        )
    except Exception as e:
        print(f"  [error] no se pudo consultar la API de GHSAs: {e}")
        sys.exit(1)

    if result.returncode != 0:
        print(f"  [error] gh api fallo: {result.stderr.strip()}")
        print("  Las cifras publicadas NO se actualizan a ciegas. Abortando.")
        sys.exit(1)

    states = [s.strip() for s in result.stdout.splitlines() if s.strip()]
    if not states:
        print("  [error] la API no devolvio ningun advisory. Abortando por las dudas.")
        sys.exit(1)

    published = states.count("published")
    draft = states.count("draft")
    closed = states.count("closed")
    counts = {
        "published": published,
        "draft": draft,
        "closed": closed,
        "filed": published + draft,
    }
    print(f"  API ok — {counts['filed']} presentadas: {published} publicadas, "
          f"{draft} en disclosure ({closed} cerradas, no cuentan)")
    return counts


def sync_yaml_counts(counts: dict) -> None:
    """
    Escribe de vuelta los conteos al yaml, para que deje de ser una tercera version a mano.

    Reemplazo por regex linea a linea y NO yaml.dump: el archivo tiene cientos de lineas
    de comentarios con la metodologia de cada case study, y yaml.dump los borraria todos.
    """
    content = STATS_FILE.read_text(encoding="utf-8")
    original = content

    # Ancla en el bloque `ghsas:` para no tocar un `total:` de otra seccion.
    #
    # Si el patron no matchea, ABORTAMOS. Antes esta funcion devolvia el texto sin
    # cambios y el caller comparaba "antes vs despues": con el regex roto, los dos
    # eran iguales y el script informaba "ya estaba al dia" — indistinguible de un
    # archivo realmente sincronizado. Es el mismo fallo silencioso por el que este
    # script escribio la prosa de Corvus sobre llamascope cinco veces: un regex que
    # no matchea no puede reportar exito.
    def replace_in_ghsas(text: str, key: str, value: int) -> str:
        pattern = re.compile(
            r"(^ghsas:.*?^  " + re.escape(key) + r":[ \t]*)(\d+)",
            re.MULTILINE | re.DOTALL,
        )
        if not pattern.search(text):
            print(f"  [error] no se encontro `{key}:` dentro del bloque `ghsas:` de "
                  f"public-stats.yaml. El formato del archivo cambio: revisar el patron "
                  f"antes de confiar en cualquier cifra publicada.")
            sys.exit(1)
        return pattern.sub(lambda m: m.group(1) + str(value), text, count=1)

    content = replace_in_ghsas(content, "total", counts["filed"])
    content = replace_in_ghsas(content, "published", counts["published"])
    content = replace_in_ghsas(content, "draft", counts["draft"])

    # El comentario de cabecera afirmaba que el script actualizaba estos conteos cuando
    # no lo hacia. Ahora es cierto, y queda dicho de donde salen.
    content = content.replace(
        "# GHSAs — queried live from GitHub API by update-public.py\n"
        "# Counts below are updated by the script; descriptions are kept here for non-API context",
        "# GHSAs — total/published/draft los escribe update-public.py desde la API de GitHub.\n"
        "# NO editarlos a mano: se pisan en la proxima corrida. `published_list` si es manual\n"
        "# (el campo `finding` en prosa no existe en la API).",
    )

    if content == original:
        print("  public-stats.yaml ya estaba al dia")
    elif not DRY_RUN:
        STATS_FILE.write_text(content, encoding="utf-8")
        print(f"  public-stats.yaml actualizado — {counts['filed']}/{counts['published']}/{counts['draft']}")
    else:
        print(f"  [dry-run] public-stats.yaml quedaria en {counts['filed']}/{counts['published']}/{counts['draft']}")


def replace_section(content: str, marker: str, new_body: str) -> str:
    """Replace content between <!-- CORVUS_{marker}_START --> and <!-- CORVUS_{marker}_END -->."""
    start_tag = f"<!-- CORVUS_{marker}_START -->"
    end_tag = f"<!-- CORVUS_{marker}_END -->"
    pattern = re.compile(
        re.escape(start_tag) + r".*?" + re.escape(end_tag),
        re.DOTALL
    )
    replacement = f"{start_tag}\n{new_body}\n{end_tag}"
    if start_tag not in content:
        print(f"  [warn] marker CORVUS_{marker}_START not found in file")
        return content
    return pattern.sub(replacement, content)


def build_modules_section(stats: dict) -> str:
    lines = []
    total = stats["modules"]["total"]

    lines.append(f"{total} built-in modules covering the full OWASP MCP Top 10 plus protocol, "
                 f"elicitation, sampling, OAuth and supply chain extensions:\n")

    lines.append("### Static modules (no live tool calls)\n")
    lines.append("| Name | OWASP | What it tests |")
    lines.append("|------|-------|---------------|")
    for m in stats["modules"]["static_list"]:
        lines.append(f"| `{m['name']}` | {m['owasp']} | {m['desc']} |")

    lines.append("")
    lines.append("### Dynamic modules (live tool calls)\n")
    lines.append("| Name | OWASP | What it tests |")
    lines.append("|------|-------|---------------|")
    for m in stats["modules"]["dynamic_list"]:
        lines.append(f"| `{m['name']}` | {m['owasp']} | {m['desc']} |")

    lines.append("")
    lines.append("### Module groups\n")
    lines.append("```bash")
    lines.append("# All modules (default)")
    lines.append("--module all\n")
    lines.append("# Static only (no live calls to the server)")
    lines.append("--module static\n")
    lines.append("# Dynamic only")
    lines.append("--module dynamic\n")
    lines.append("# Individual module")
    lines.append("--module cmd-injection")
    lines.append("```")

    return "\n".join(lines)


def build_research_section(stats: dict) -> str:
    cs = stats["case_studies"]
    t = cs["totals"]
    kf = stats.get("key_findings", [])
    cs_count = len([k for k in cs if k != "totals"])

    count_words = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five",
                   6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten"}
    cs_word = count_words.get(cs_count, str(cs_count))

    lines = []
    lines.append(f"Corvus has been battle-tested against the real-world MCP ecosystem across {cs_word} case studies "
                 f"— {t['servers']} servers audited, spanning official `@modelcontextprotocol` packages, "
                 f"community servers, and the broader npm and PyPI ecosystem.\n")

    lines.append(f"| Metric | Total ({cs_count} case studies) |")
    lines.append(f"|--------|-------------------------------|")
    lines.append(f"| Servers audited | **{t['servers']}** |")
    lines.append(f"| Raw findings | **~{t['raw_findings']}** |")
    lines.append(f"| True positives | **~{t['true_positives']}** |")

    lines.append("")
    lines.append("Key findings from the wild:\n")
    for f in kf:
        lines.append(f"- **{f}**" if not f.startswith("**") else f"- {f}")

    lines.append("")
    lines.append("Full datasets, curated findings, and methodology in [`case-studies/`](case-studies/).")

    return "\n".join(lines)


def build_disclosure_section(stats: dict, counts: dict) -> str:
    g = stats["ghsas"]
    published_list = g["published_list"]
    total = counts["filed"]
    published = counts["published"]
    draft = counts["draft"]

    lines = []
    cs_count = len([k for k in stats.get("case_studies", {}) if k != "totals"])
    lines.append(f"{total} security advisories filed across {cs_count} case studies "
                 f"— {published} published, {draft} in active coordinated disclosure (90-day window).\n")

    lines.append("**Published:**\n")
    lines.append("| Advisory | Package | Severity | Finding |")
    lines.append("|----------|---------|----------|---------|")
    for p in published_list:
        # Repository advisory: la forma corta github.com/advisories/<id> devuelve 404.
        url = f"https://github.com/{ADVISORY_REPO}/security/advisories/{p['ghsa']}"
        lines.append(f"| [{p['ghsa']}]({url}) | {p['pkg']} | {p['sev']} | {p['finding']} |")

    # `published_list` es manual (el campo `finding` no existe en la API), asi que puede
    # quedar corta respecto del conteo vivo. Se declara en vez de disimularlo.
    listed = len(published_list)
    if listed < published:
        lines.append("")
        lines.append(f"> Listing {listed} of {published} published advisories — the remaining "
                     f"{published - listed} are public on the GitHub Advisory Database and pending "
                     f"a curated description here.")

    lines.append("")
    lines.append(f"**Active coordinated disclosure ({draft} advisories):** 90-day embargo window in progress.")
    lines.append("")
    lines.append("Full advisory index: [`case-studies/DISCLOSURE-PROCESS.md`](case-studies/DISCLOSURE-PROCESS.md)")

    return "\n".join(lines)


def update_readme(stats: dict, counts: dict) -> None:
    content = README.read_text(encoding="utf-8")

    content, n_ver = re.subn(r"Corvus v\d+\.\d+\.\d+", f"Corvus v{stats['version']}", content)
    if n_ver:
        print(f"  Fixed version: → Corvus v{stats['version']} ({n_ver} occurrence{'s' if n_ver != 1 else ''})")

    content = replace_section(content, "MODULES", build_modules_section(stats))
    content = replace_section(content, "RESEARCH", build_research_section(stats))
    content = replace_section(content, "DISCLOSURE", build_disclosure_section(stats, counts))

    if not DRY_RUN:
        README.write_text(content, encoding="utf-8")
        print("  README.md updated")
    else:
        print("  [dry-run] README.md would be updated")


def build_web_stats(stats: dict, counts: dict) -> dict:
    """
    Payload para la web: SOLO numeros y strings cortos de identificacion.

    Nada de prosa. Si alguna vez hace falta agregar una frase aca, la respuesta es no:
    la prosa vive en el repo de la web, escrita por una persona, e interpola estos valores.
    """
    t = stats["case_studies"]["totals"]
    m = stats["modules"]
    cs_count = len([k for k in stats["case_studies"] if k != "totals"])

    return {
        "_source": "corvus/scripts/update-public.py — no editar a mano",
        "_generatedFrom": {
            "advisories": f"GitHub API (repos/{ADVISORY_REPO}/security-advisories)",
            "resto": "corvus/case-studies/public-stats.yaml",
        },
        "asOf": date.today().isoformat(),
        "corvusVersion": stats["version"],
        "campaignRange": f"CS-01 – CS-{cs_count:02d}",
        "serversAudited": t["servers"],
        "totalFindings": t["raw_findings"],
        "truePositives": t["true_positives"],
        "advisoriesFiled": counts["filed"],
        "advisoriesPublished": counts["published"],
        "modulesStatic": m["static"],
        "modulesDynamic": m["dynamic"],
        "tests": stats["tests_unit"],
    }


def write_web_stats(stats: dict, counts: dict) -> None:
    payload = build_web_stats(stats, counts)

    # Coherencia antes de escribir: si la aritmetica no cierra, no se publica.
    if payload["advisoriesFiled"] != counts["published"] + counts["draft"]:
        print("  [error] filed != published + draft. Abortando.")
        sys.exit(1)
    if payload["modulesStatic"] + payload["modulesDynamic"] != stats["modules"]["total"]:
        print(f"  [error] modules: {payload['modulesStatic']} + {payload['modulesDynamic']} "
              f"!= {stats['modules']['total']} (yaml). Corregir public-stats.yaml.")
        sys.exit(1)

    body = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"

    if DRY_RUN:
        print("  [dry-run] corvus-stats.json quedaria asi:")
        print("\n".join(f"    {line}" for line in body.splitlines()))
        return

    if not WEB_GENERATED.exists():
        print(f"  [error] no existe {WEB_GENERATED} — el repo de la web no esta donde se espera.")
        sys.exit(1)

    WEB_STATS_JSON.write_text(body, encoding="utf-8")
    print(f"  {WEB_STATS_JSON} escrito — {payload['advisoriesFiled']} presentadas, "
          f"{payload['advisoriesPublished']} publicadas, asOf {payload['asOf']}")


def main():
    print("Loading stats...")
    stats = load_stats()
    print(f"  Version: {stats['version']}, Modules: {stats['modules']['total']}, "
          f"Tests: {stats['tests_unit']}")

    print("\nFetching live GHSA counts...")
    counts = fetch_ghsa_counts()

    print("\nSyncing public-stats.yaml counts...")
    sync_yaml_counts(counts)

    print("\nUpdating README.md...")
    update_readme(stats, counts)

    print("\nWriting web stats JSON...")
    write_web_stats(stats, counts)

    print("\nDone." + (" (dry run — no files written)" if DRY_RUN else ""))
    print("La web NO se toca desde aca mas alla del JSON: la prosa de toolsData.ts y")
    print("projectsData.ts es editorial y se edita a mano en CobaltoSec-Web.")


if __name__ == "__main__":
    main()

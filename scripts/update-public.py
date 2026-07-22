#!/usr/bin/env python3
"""
Sync public-facing docs from case-studies/public-stats.yaml + live GitHub GHSA API.

Usage:
    python scripts/update-public.py [--dry-run]

Updates:
    - README.md          (between <!-- CORVUS_xxx_START --> markers)
    - CobaltoSec-Web/data/projectsData.ts
    - CobaltoSec-Web/data/toolsData.ts
"""

import json
import re
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("pip install pyyaml")
    sys.exit(1)

ROOT = Path(__file__).parent.parent
STATS_FILE = ROOT / "case-studies" / "public-stats.yaml"
README = ROOT / "README.md"
WEB_ROOT = Path("C:/Proyectos/CobaltoSec-Web/data")
PROJECTS_TS = WEB_ROOT / "projectsData.ts"
TOOLS_TS = WEB_ROOT / "toolsData.ts"

DRY_RUN = "--dry-run" in sys.argv


def load_stats() -> dict:
    with open(STATS_FILE) as f:
        return yaml.safe_load(f)


def fetch_ghsas_live() -> dict:
    """Query GitHub API for current GHSA counts."""
    try:
        result = subprocess.run(
            ["gh", "api", "repos/CobaltoSec/advisories/security-advisories",
             "--paginate", "--jq", ".[] | .state"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            print(f"  [warn] gh api failed: {result.stderr.strip()}")
            return {}
        states = [s.strip() for s in result.stdout.strip().splitlines() if s.strip()]
        corvus_total = len([s for s in states if True])  # all in our repo are either corvus or shrike
        # We can't distinguish corvus vs shrike via API alone — use stats yaml values
        return {"api_ok": True, "raw_states": states}
    except Exception as e:
        print(f"  [warn] Could not fetch GHSAs: {e}")
        return {}


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
    static_count = stats["modules"]["static"]
    dyn_count = stats["modules"]["dynamic"]

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

    # Map count to English word
    count_words = {1:"one",2:"two",3:"three",4:"four",5:"five",6:"six",7:"seven",8:"eight",9:"nine",10:"ten"}
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


def build_disclosure_section(stats: dict) -> str:
    g = stats["ghsas"]
    published = g["published_list"]
    total = g["total"]
    draft = g["draft"]

    lines = []
    cs_count = len([k for k in stats.get("case_studies", {}) if k != "totals"])
    lines.append(f"{total} security advisories filed across {cs_count} case studies "
                 f"— {g['published']} published, {draft} in active coordinated disclosure (90-day window).\n")

    lines.append("**Published:**\n")
    lines.append("| Advisory | Package | Severity | Finding |")
    lines.append("|----------|---------|----------|---------|")
    for p in published:
        url = f"https://github.com/advisories/{p['ghsa']}"
        lines.append(f"| [{p['ghsa']}]({url}) | {p['pkg']} | {p['sev']} | {p['finding']} |")

    lines.append("")
    lines.append(f"**Active coordinated disclosure ({draft} advisories):** packages include "
                 f"@playwright/mcp, mcp-server-sqlite, mcp-shell-server, myclaw-toolkit (CRITICAL), "
                 f"@sap-ux/fiori-mcp-server, and others — 90-day embargo window in progress.")
    lines.append("")
    lines.append("Full advisory index: [`case-studies/DISCLOSURE-PROCESS.md`](case-studies/DISCLOSURE-PROCESS.md)")

    return "\n".join(lines)


def update_readme(stats: dict) -> None:
    content = README.read_text(encoding="utf-8")

    # Fix version in demo block (regex, works regardless of previous version)
    content, n_ver = re.subn(r"Corvus v\d+\.\d+\.\d+", f"Corvus v{stats['version']}", content)
    if n_ver:
        print(f"  Fixed version: → Corvus v{stats['version']} ({n_ver} occurrence{'s' if n_ver != 1 else ''})")

    # Replace marked sections
    content = replace_section(content, "MODULES", build_modules_section(stats))
    content = replace_section(content, "RESEARCH", build_research_section(stats))
    content = replace_section(content, "DISCLOSURE", build_disclosure_section(stats))

    if not DRY_RUN:
        README.write_text(content, encoding="utf-8")
        print("  README.md updated")
    else:
        print("  [dry-run] README.md would be updated")


def update_projects_ts(stats: dict) -> None:
    if not PROJECTS_TS.exists():
        print(f"  [warn] {PROJECTS_TS} not found")
        return

    cs = stats["case_studies"]
    t = cs["totals"]
    g = stats["ghsas"]
    content = PROJECTS_TS.read_text(encoding="utf-8")

    # Replace the Corvus description string (between the description: ' ... ' quotes)
    old_pattern = re.compile(
        r"(title:\s*'Corvus[^']*'.*?description:\s*\n?\s*')([^']+)(')",
        re.DOTALL
    )
    new_desc = (
        f"MCP ecosystem security audit framework. {t['servers']} production MCP servers audited "
        f"with Corvus (OWASP MCP Top 10 scanner). Result: ~{t['raw_findings']} findings, "
        f"~{t['true_positives']} confirmed true positives, {g['total']} responsible disclosures "
        f"({g['published']} published, {g['draft']} in coordinated 90-day disclosure)."
    )
    new_content = old_pattern.sub(lambda m: m.group(1) + new_desc + m.group(3), content)

    # Update metrics[] array card values
    metrics_map = [
        ('Servers audited', str(t['servers'])),
        ('True positives', str(t['true_positives'])),
        ('Advisories filed', str(g['total'])),
    ]
    for label, value in metrics_map:
        pat = re.compile(
            r"(\{\s*label:\s*'" + re.escape(label) + r"',\s*value:\s*')\d+(')"
        )
        new_content = pat.sub(lambda m, v=value: m.group(1) + v + m.group(2), new_content)

    if not old_pattern.search(content):
        print("  [warn] projectsData.ts: pattern not matched, manual update needed")
    elif new_content == content:
        print("  projectsData.ts already up-to-date")
    elif not DRY_RUN:
        PROJECTS_TS.write_text(new_content, encoding="utf-8")
        print("  projectsData.ts updated")
    else:
        print("  [dry-run] projectsData.ts would be updated")


def update_tools_ts(stats: dict) -> None:
    if not TOOLS_TS.exists():
        print(f"  [warn] {TOOLS_TS} not found")
        return

    cs = stats["case_studies"]
    t = cs["totals"]
    g = stats["ghsas"]
    m = stats["modules"]
    cs_count = len([k for k in cs if k != "totals"])
    content = TOOLS_TS.read_text(encoding="utf-8")

    # Replace tagline
    old_tagline_pat = re.compile(r"(slug:\s*'corvus'.*?tagline:\s*')([^']+)(')", re.DOTALL)
    new_tagline = f"OWASP MCP Top 10 scanner — {g['total']} advisories filed, {g['published']} published"
    new_content = old_tagline_pat.sub(lambda m_: m_.group(1) + new_tagline + m_.group(3), content)

    # Replace description
    old_desc_pat = re.compile(
        r"(slug:\s*'corvus'.*?description:\s*\n?\s*')([^']+)(')",
        re.DOTALL
    )
    new_desc = (
        f"Framework for auditing MCP servers against the OWASP MCP Top 10. "
        f"{m['total']} modules ({m['static']} static + {m['dynamic']} dynamic), {stats['tests_unit']} tests. "
        f"CS01–CS{cs_count:02d}: {t['servers']} real production servers audited, ~{t['true_positives']} confirmed vulnerabilities. "
        f"{g['total']} responsible disclosures: {g['published']} published — "
        + ", ".join(f"{p['ghsa']} ({p['pkg']})" for p in g["published_list"][:2])
        + f", and {g['total'] - 2} more."
    )
    new_content = old_desc_pat.sub(lambda m_: m_.group(1) + new_desc + m_.group(3), new_content)

    tagline_matched = bool(old_tagline_pat.search(content))
    desc_matched = bool(old_desc_pat.search(content))
    if not tagline_matched or not desc_matched:
        print(f"  [warn] toolsData.ts: pattern not matched (tagline={tagline_matched}, desc={desc_matched}), manual update needed")
    elif new_content == content:
        print("  toolsData.ts already up-to-date")
    elif not DRY_RUN:
        TOOLS_TS.write_text(new_content, encoding="utf-8")
        print("  toolsData.ts updated")
    else:
        print("  [dry-run] toolsData.ts would be updated")


def main():
    print("Loading stats...")
    stats = load_stats()
    print(f"  Version: {stats['version']}, Modules: {stats['modules']['total']}, "
          f"GHSAs: {stats['ghsas']['total']} ({stats['ghsas']['published']} published)")

    print("\nFetching live GHSA data...")
    live = fetch_ghsas_live()
    if live.get("api_ok"):
        print(f"  API ok — {len(live['raw_states'])} total advisories in repo")

    print("\nUpdating README.md...")
    update_readme(stats)

    print("\nUpdating CobaltoSec-Web/data/projectsData.ts...")
    update_projects_ts(stats)

    print("\nUpdating CobaltoSec-Web/data/toolsData.ts...")
    update_tools_ts(stats)

    print("\nDone." + (" (dry run — no files written)" if DRY_RUN else ""))


if __name__ == "__main__":
    main()

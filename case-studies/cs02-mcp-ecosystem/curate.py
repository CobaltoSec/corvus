#!/usr/bin/env python3
"""CS02 Curation — classifies candidates as KEEP/SKIP with reasons.

Reads candidates.yaml, applies layered rules, merges with manual additions
from prior scraper runs, outputs:
  - curated-keep.yaml   — KEEP list (merged, deduped)
  - curated-skip.yaml   — SKIP list with reasons (audit trail)
  - tier-d-curated.yaml — ready-to-paste entries for targets-master.yaml

Usage:
  python curate.py
"""
from pathlib import Path
import yaml

HERE = Path(__file__).parent
CANDIDATES = HERE / "candidates.yaml"
KEEP_OUT   = HERE / "curated-keep.yaml"
SKIP_OUT   = HERE / "curated-skip.yaml"
SNIPPET    = HERE / "tier-d-curated.yaml"

# ── Skip rules ────────────────────────────────────────────────────────────────

SKIP_EXACT = {
    # Meta / framework packages
    "mcp-server",
    "@claude-flow/mcp",
    "@planu/cli",
    "@planu/core-win32-arm64-msvc",
    "middy-mcp",
    "@mcpmarket/mcp-auto-install",
    "@dallay/agentsync",
    "@exaudeus/workrail",
    "@takuhon/mcp",
    "@knip/mcp",
    "@modelstat/mcp",
    "@commercetools/processors",
    "@penclipai/mcp-server",
    "paput-mcp",
    "handoff-mcp-server",
    "@aws/nx-plugin-mcp",
    "@svelte-vitals/mcp",
    "@miraigent/free-ai-ops-mcp",
    "claude-faf-mcp",
    "sqlew",

    # Explicit SaaS / auth-required
    "hlims-mcp",
    "@paperclipai/mcp-server",
    "@ragieai/mcp-server",
    "@delorenj/mcp-server-ticketmaster",
    "mcp-deepseek",
    "@diskd-ai/email-mcp",
    "@esaio/esa-mcp-server",
    "feishu-mcp",
    "@a-bonus/google-docs-mcp",
    "dataforseo-mcp-server",
    "polaris-mcp-server",
    "@n8n-mcp-server",
    "@leonardsellem/n8n-mcp-server",
    "@ehrocks/fe-mcp-server",
    "@assistant-ui/mcp-docs-server",
    "@seed-design/docs-mcp",
    "@tankpkg/mcp-server",
    "nuvex-mcp-server",
    "@apex-inc/mcp-server",
    "@insforge/mcp",
    "@clize/clize",
    "@cachly-dev/mcp-server",
    "shantycrawl-mcp",
    "@grackle-ai/mcp",
    "@refrakt-md/mcp",
    "distribea-mcp",
    "mcp-image",
    "figura-mcp",
    "@avallon-labs/mcp",
    "@avodado/mcp",
    "rosetta-mcp-server",
    "codefizz-editor-agent",
    "codex-mcp-server",
    "@stableops/mcp-server",
    "@iqai/mcp-polymarket",
    "@diagrammo/dgmo-mcp",
    "@weppy/roblox-mcp",
    "12306-mcp",
    "mcp-obsidian",
    "yapi-auto-mcp",
    "@peekdev/mcp",
    "semiotic",

    # Platform-specific / needs special runtime
    "ios-simulator-mcp",
    "xcodebuildmcp",
    "@k8ika0s/mcp-tmux",
    "camoufox-mcp-server",
    "@hypothesi/tauri-mcp-server",
    "@n24q02m/better-godot-mcp",
    "@n24q02m/better-email-mcp",
    "@mcp-abap-adt/core",
    "@mcp-apps/kusto-mcp-server",

    # Siemens duplicates
    "@siemens/ix-mcp-react",
    "@siemens/ix-mcp-angular",

    # Needs external service instance
    "@anyproto/anytype-mcp",
    "mcp-server-ticktick",
    "@browserless.io/mcp",
    "@gitee/mcp-gitee",
    "iobroker.mcp",
    "@iobroker/mcp-server",
    "@diviops/mcp-server",
    "@respira/wordpress-mcp-server",
    "@unified-product-graph/cli",
    "@cablate/mcp-google-map",
    "@codacy/codacy-mcp",
    "@mcp-apps/kusto-mcp-server",

    # Run2 false positives — auth/account/instance required
    "slack-mcp-server",
    "@ironbee-ai/devtools",
    "@translated/lara-mcp",
    "docusaurus-plugin-mcp-server",
    "storybook-mcp-server",
    "@mgsoftwarebv/mcp-server-bridge",
    "kapture-mcp",
    "@qase/mcp-server",
    "@delorenj/mcp-server-trello",
    "@ohah/react-native-mcp-server",
    "@runpod/mcp-server",
    "@line/line-bot-mcp-server",
    "@extentos/mcp-server",
    "@gleanwork/local-mcp-server",
    "agentmail-mcp",
    "@socialneuron/mcp-server",
    "@r-huijts/strava-mcp-server",
    "@kintone/mcp-server",
    "targetprocess-mcp-server",
    "@transloadit/mcp-server",
    "@codefuturist/email-mcp",
    "@vapi-ai/mcp-server",
    "@convertcom/mcp-server",
    "deepl-mcp-server",
}

SKIP_NAME_CONTAINS = [
    "azure", "aws-", "gcp", "google-cloud",
    "perplexity", "apify", "brave-search", "alchemy/mcp",
    "atlassian", "microsoft/", "powerbi",
    "salesforce", "hubspot", "stripe", "twilio", "sendgrid",
    "datadog", "pagerduty", "dynatrace", "newrelic",
    "snowflake", "databricks", "pinecone", "weaviate",
    "firebase", "supabase", "neon", "planetscale",
    "kubernetes", "argocd", "argo-cd",
    "hostinger", "heroku",
    "shortcut/mcp", "unthread", "trustpager", "doitintl",
    "browserstack", "suthio/redash", "arizeai",
    "smartbear", "aikidosec", "vantasdk",
    "growthbook", "currents/mcp",
    "leadshark", "cariot",
    "rhombus-node", "configcat",
    "rushdb", "tolgee",
    "linkup-mcp", "serper-search",
    "overpod/mcp-telegram",
    "atomicmail", "atomic-mail",
    "z_ai/mcp",
    "@mapbox",
    "vibeframe",
    "gorgias-mcp",
    "outline-mcp-server", "outline-mcp",
    "slite-mcp", "redmine-mcp",
    "solapi", "insforge", "commercetools",
    "hauntapi", "dbx-app",
    "oxis-dev/tessra",
    "refrakt-md",
    "metabase-mcp",
    "thelabnyc/redmine",
    "cognitionai",
    "@klip", "kibana",
    "listhenxydlgzs", "lishenxydlgzs",
]

SKIP_DESC_CONTAINS = [
    "private beta",
    "requires an account",
    "requires a valid",
    "api key required",
    "proof-of-work auth",
    "bearer token",
    "stablecoin",
    "cryptocurrency",
    "blockchain",
    "wallet",
]

# ── Manual additions — run1 (threshold=500) packages not in run2 candidates.yaml
# These are genuinely batchable but fell out of run2 due to npm search variance.
# Format: (name, description, weekly_downloads)
MANUAL_ADDITIONS = [
    ("nx-mcp",                             "Nx monorepo dev tools — code gen, migration, project graph", 58168),
    ("obsidian-mcp-server",                "Obsidian vault read/write via REST API plugin",              5866),
    ("@ericthered926/duckduckgo-mcp-server","DuckDuckGo search integration",                            4055),
    ("flightradar-mcp-server",             "Flight tracking via Flightradar24 public API",              3625),
    ("@cyanheads/pubmed-mcp-server",       "PubMed biomedical literature search — public API",          3385),
    ("@jpisnice/shadcn-ui-mcp-server",     "shadcn/ui component docs and generation",                   3046),
    ("@wopal/mcp-server-hotnews",          "Chinese trending topics aggregator — public scraping",      2944),
    ("@mzxrai/mcp-webresearch",            "Web research + scraping via Puppeteer",                     2201),
    ("korean-law-mcp",                     "Korean law database — public API",                          2039),
    ("@remnux/mcp-server",                 "REMnux malware analysis toolkit — shell + file ops",        1813),
    ("@idachev/mcp-javadc",                "Java decompiler — binary analysis surface",                 1767),
    ("@kazuph/mcp-fetch",                  "Fetch URL + save images — SSRF + path write",              1729),
    ("@usejunior/docx-mcp",                "DOCX read/write operations",                               1478),
    ("@spartan-ng/mcp",                    "Spartan Angular UI component docs",                         1455),
    ("mcp-postgres",                       "PostgreSQL MCP — query execution (test DB)",                1396),
    ("@jinzcdev/markmap-mcp-server",       "Markmap mind-map generation from Markdown",                 1319),
    ("@just-every/mcp-read-website-fast",  "Fast web content fetch — SSRF surface",                    1233),
    ("@just-every/mcp-screenshot-website-fast", "Screenshot via Puppeteer — SSRF + headless browser",  1138),
    ("mysql-mcp-server",                   "MySQL read-only queries (test DB)",                         1060),
    ("drawio-mcp-server",                  "Draw.io diagram editing — file I/O surface",                 925),
    ("@get-technology-inc/jamf-docs-mcp-server", "Jamf MDM documentation server",                       905),
    ("european-parliament-mcp-server",     "EU Parliament open data — public API",                       889),
    ("@j0hanz/fetch-url-mcp",              "URL fetch → markdown conversion — SSRF surface",             839),
    ("myclaw-toolkit",                     "23-in-1 dev toolkit: search, crypto, QR, rates, etc.",       787),
    ("@berthojoris/mcp-mysql-server",      "MySQL per-project permission model — SQL surface",           636),
    ("@harusame64/desktop-touch-mcp",      "Windows desktop automation — 29 tools, huge attack surface", 573),
]

# ── Security notes ────────────────────────────────────────────────────────────

SECURITY_NOTES = {
    # High attack surface — execution
    "malicious-mcp-server":              "deliberately malicious server — high attack surface by design",
    "@remnux/mcp-server":                "REMnux malware toolkit — shell + file ops attack surface",
    "mcp-server-code-runner":            "code runner — execution attack surface",
    "@wonderwhy-er/desktop-commander":   "terminal + file editing (30+ tools) — huge attack surface",
    "mcp-server-docker":                 "Docker container exec — container escape surface",
    "@fangjunjie/ssh-mcp-server":        "SSH wrapper — auth bypass + lateral movement surface",
    "@harusame64/desktop-touch-mcp":     "Windows desktop automation (29 tools) — huge attack surface",
    "nx-mcp":                            "Nx monorepo — code execution + file system surface",

    # SSRF / web
    "fetcher-mcp":                       "HTTP fetcher via Playwright — SSRF attack surface",
    "@kazuph/mcp-fetch":                 "web fetcher + image save — SSRF + path write",
    "@j0hanz/fetch-url-mcp":             "web fetch → markdown — SSRF attack surface",
    "@just-every/mcp-screenshot-website-fast": "screenshot via Puppeteer — SSRF + headless browser",
    "@just-every/mcp-read-website-fast": "web content fetch — SSRF attack surface",
    "@mzxrai/mcp-webresearch":           "web research + scraping — SSRF",

    # File / path ops
    "obsidian-mcp-server":               "Obsidian vault R/W — file system access",
    "@usejunior/docx-mcp":               "DOCX read/write — file processing + path ops",
    "@idachev/mcp-javadc":               "Java decompiler — file processing surface",
    "drawio-mcp-server":                 "Draw.io diagrams — file I/O surface",
    "@unified-product-graph/mcp-server": "local .upg file graph — path traversal surface",

    # Database
    "mcp-postgres":                      "PostgreSQL — SQL injection surface (test DB)",
    "mysql-mcp-server":                  "MySQL read-only — SQL surface (test DB)",
    "@berthojoris/mcp-mysql-server":     "MySQL per-project permissions — SQL injection surface",
    "@henkey/postgres-mcp-server":       "PostgreSQL management — SQL injection surface (test DB)",

    # LSP / code intelligence
    "lsp-mcp-server":                    "LSP bridge — protocol attack surface",
    "cclsp":                             "LSP access — code intelligence attack surface",

    # Schema / protocol surface
    "@ui5/mcp-server":                   "SAP UI5 dev tools — large schema surface",
    "@drawio/mcp":                       "Official Draw.io — diagram tool surface",
    "mcp-server-nationalparks":          "NPS public API — schema quality surface",
    "flightradar-mcp-server":            "flight tracking — public API surface",
    "@wopal/mcp-server-hotnews":         "Chinese trending topics — public API scraping",
    "@professional-wiki/mediawiki-mcp-server": "MediaWiki — public API + write surface",
    "@cyanheads/pubmed-mcp-server":      "PubMed public API — large schema surface",
    "korean-law-mcp":                    "Korean law public API — schema + injection surface",
    "european-parliament-mcp-server":    "EU Parliament open data — public API surface",
    "@siemens/element-mcp":              "Siemens Element design system — schema quality",
    "@mantine/mcp-server":               "Mantine UI docs — schema quality",
    "@jpisnice/shadcn-ui-mcp-server":    "shadcn/ui docs — schema quality",
    "@spartan-ng/mcp":                   "Spartan Angular UI docs — schema quality",
    "@ericthered926/duckduckgo-mcp-server": "DuckDuckGo search — web interaction surface",

    # Tool injection / prompt injection surface
    "playwright-mcp-server":             "Playwright test generator (distinct from @playwright/mcp) — schema surface",
    "agent-orchestrator-mcp-server":     "agent orchestrator — tool injection + scope surface",
    "@kernlang/mcp-server":              "KERN DSL compiler — code exec + file write surface",
}


def should_skip(name: str, desc: str) -> tuple[bool, str]:
    if name in SKIP_EXACT:
        return True, f"explicit skip: {name}"
    name_lower = name.lower()
    for pat in SKIP_NAME_CONTAINS:
        if pat in name_lower:
            return True, f"auth-required service in name: '{pat}'"
    desc_lower = desc.lower()
    for pat in SKIP_DESC_CONTAINS:
        if pat in desc_lower:
            return True, f"auth pattern in description: '{pat}'"
    return False, ""


def make_entry(name: str, desc: str, downloads: int) -> dict:
    display = name.split("/")[-1] if "/" in name else name
    note = desc.strip()
    if name in SECURITY_NOTES:
        note = f"{note}. ★ {SECURITY_NOTES[name]}"
    note += f" {downloads:,}/wk."
    return {
        "name": display,
        "tier": "D",
        "transport": "stdio",
        "cmd": ["npx", "-y", name],
        "status": "pending",
        "notes": note,
    }


def main():
    with CANDIDATES.open() as f:
        data = yaml.safe_load(f)

    candidates = data.get("candidates", [])
    print(f"[*] Loaded {len(candidates)} candidates from scraper run")

    # ── Pass 1: filter scraper candidates ────────────────────────────────────
    keep_from_scraper, skip = [], []
    for c in candidates:
        skipped, reason = should_skip(c["name"], c.get("description", ""))
        if skipped:
            skip.append({**c, "skip_reason": reason})
        else:
            keep_from_scraper.append(c)

    print(f"[*] Scraper candidates → KEEP: {len(keep_from_scraper)}  SKIP: {len(skip)}")

    # ── Pass 2: merge manual additions (run1 packages not in scraper run) ────
    scraper_names = {c["name"] for c in keep_from_scraper}
    manual_kept = 0
    for name, desc, downloads in MANUAL_ADDITIONS:
        if name in scraper_names:
            continue  # already covered by scraper run
        skipped, reason = should_skip(name, desc)
        if skipped:
            skip.append({"name": name, "description": desc,
                         "weekly_downloads": downloads, "skip_reason": reason})
        else:
            keep_from_scraper.append({
                "name": name, "description": desc,
                "weekly_downloads": downloads,
                "has_bin": True, "auth_required": False,
                "keywords": [], "version": "latest",
            })
            manual_kept += 1

    keep = sorted(keep_from_scraper, key=lambda x: x["weekly_downloads"], reverse=True)
    print(f"[*] Manual additions merged: {manual_kept} new")
    print(f"[*] Final KEEP: {len(keep)}  |  Total SKIP: {len(skip)}")

    # ── Display ───────────────────────────────────────────────────────────────
    print("\n── KEEP (top 30 by downloads) ──────────────────────────────────")
    for c in keep[:30]:
        marker = "★" if c["name"] in SECURITY_NOTES else " "
        print(f"  {marker} {c['weekly_downloads']:>8,}  {c['name']}")
    if len(keep) > 30:
        print(f"  ... and {len(keep) - 30} more")

    print("\n── SKIP (sample) ───────────────────────────────────────────────")
    for c in skip[:15]:
        print(f"  {c.get('weekly_downloads', 0):>8,}  {c['name']:40s}  ← {c['skip_reason']}")
    if len(skip) > 15:
        print(f"  ... and {len(skip) - 15} more")

    # ── Write outputs ─────────────────────────────────────────────────────────
    with KEEP_OUT.open("w") as f:
        yaml.dump({"total": len(keep), "candidates": keep}, f,
                  default_flow_style=False, allow_unicode=True)

    with SKIP_OUT.open("w") as f:
        yaml.dump({"total": len(skip), "candidates": skip}, f,
                  default_flow_style=False, allow_unicode=True)

    entries = [make_entry(c["name"], c.get("description", ""), c["weekly_downloads"])
               for c in keep]
    with SNIPPET.open("w") as f:
        yaml.dump(entries, f, default_flow_style=False, allow_unicode=True)

    print(f"\n[+] curated-keep.yaml   → {KEEP_OUT}  ({len(keep)} targets)")
    print(f"[+] curated-skip.yaml   → {SKIP_OUT}  ({len(skip)} skipped)")
    print(f"[+] tier-d-curated.yaml → {SNIPPET}  (ready to paste)")
    print(f"\n[✓] Final Tier D: {len(keep)} new servers  +  23 existing  =  {len(keep)+23} total")


if __name__ == "__main__":
    main()

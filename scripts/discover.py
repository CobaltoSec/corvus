#!/usr/bin/env python3
"""
discover.py — Internal MCP server discovery script (CobaltoSec / Corvus)

Queries npm registry for new MCP server candidates, cross-references against
existing Corvus dataset (CS01–CS04), applies a no-auth heuristic, and outputs
a targets YAML in the standard corvus batch/tracking format.

Usage:
    python scripts/discover.py
    python scripts/discover.py --min-downloads 500
    python scripts/discover.py --include-maybe-auth --top 200
    python scripts/discover.py --output-dir case-studies/cs05-mcp-ecosystem

Output files (in --output-dir):
    candidates-YYYY-MM-DD.yaml   — ready for corvus batch + manual tracking
    skipped-YYYY-MM-DD.txt       — packages filtered out (auth / low downloads)
"""

from __future__ import annotations

import asyncio
import argparse
import re
import sys
from datetime import date
from pathlib import Path
from typing import Optional

import httpx
import yaml

# ── Constants ─────────────────────────────────────────────────────────────────

CORVUS_ROOT = Path(__file__).parent.parent

# npm API endpoints
NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
NPM_DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-week"
NPM_REGISTRY_URL = "https://registry.npmjs.org"

NPM_QUERIES = [
    "mcp-server",
    "mcp server",
    "model-context-protocol server",
    "mcp tool",
    # Round 2 — more specific angles
    "claude mcp",
    "cursor mcp",
    "mcp tools server",
    "mcp stdio server",
]

# Keywords in name/description/keywords that strongly suggest auth required
AUTH_SIGNALS = [
    # LLM providers
    "openai", "anthropic", "gemini", "gpt", "claude api",
    # SaaS platforms / productivity
    "slack", "notion", "github", "gitlab", "bitbucket",
    "jira", "confluence", "atlassian", "linear", "asana",
    "trello", "monday", "clickup", "basecamp",
    "zendesk", "freshdesk", "intercom",
    "salesforce", "hubspot",
    "todoist", "ticktick", "things3", "omnifocus",
    "obsidian", "roam research", "logseq", "notion",
    "airtable", "coda.io", "smartsheet",
    # Cloud providers
    "aws ", "azure", " gcp ", "google cloud",
    "s3 bucket", "lambda", "cloudflare", "vercel",
    "netlify", "heroku", "railway", "digitalocean",
    "supabase", "firebase", "planetscale", "neon",
    # Travel / booking (require API keys: Amadeus, Skyscanner, etc.)
    "flight", "hotel booking", "train ticket", "car rental", "ferr",
    "booking.com", "expedia", "kayak", "skyscanner", "amadeus",
    # Payments
    "stripe", "paypal", "shopify",
    # Email/comms
    "twilio", "sendgrid", "mailchimp", "mailgun",
    "telegram bot", "discord bot", "whatsapp",
    # Social
    "twitter", "instagram", "linkedin", "spotify", "youtube",
    # Search services (paid)
    "brave search", "tavily", "exa search", "perplexity",
    "serper", "alpha vantage", "polygon.io",
    # Auth
    "okta", "auth0",
    # Monitoring
    "datadog", "sentry", "newrelic", "pagerduty",
    # Figma/design
    "figma api",
]

# Keywords that strongly suggest no-auth / public APIs
NOAUTH_SIGNALS = [
    # Reference databases
    "wikipedia", "wikidata", "wikimedia",
    "arxiv", "pubmed", "pubchem", "openalex", "semantic scholar",
    "crossref", "orcid", "doi",
    "hacker news", "hackernews", " hn ",
    "open library", "internet archive",
    "smithsonian",
    # Government / public data
    "sec edgar", "edgar ", "us federal", "usa spending",
    "bureau of labor", " bls ",
    "cdc ", "health data",
    "eu law", "eur-lex", "european parliament",
    "clinical trials",
    "national parks",
    # Weather / geo (public)
    "open-meteo", "openmeteo", "noaa", "national weather service",
    "weather forecast", "public weather",
    # Local tools
    "filesystem", "local file", "local database",
    "sqlite", "duckdb",
    "eslint", "prettier", "typescript checker",
    "code analysis", "lint",
    # Docs servers (usually embed local data)
    "framework documentation", "component docs", "design system docs",
    "api documentation", "sdk documentation",
    # Public APIs
    "no api key", "no auth", "no authentication required",
    "free public api", "open api", "public rest api",
    "without api key",
    # Specific known public
    "yahoo finance", "mastra",
    "svelte", "vuetify", "taiga ui", "grafana design",
    "cap-js", "sap cap",
]

# ── Utilities ─────────────────────────────────────────────────────────────────

def strip_version(pkg_name: str) -> str:
    """Strip @version suffix, preserving scoped package names."""
    if pkg_name.startswith("@"):
        m = re.match(r"^(@[^/@]+/[^@]+)", pkg_name)
        return m.group(1) if m else pkg_name
    return pkg_name.split("@")[0]


def extract_pkg_from_cmd(cmd: list) -> Optional[str]:
    """Extract npm/uvx package name from cmd array, stripping version."""
    if not cmd:
        return None
    skip = {"npx", "uvx", "node", "python", "python3", "-y", "--yes", "-m",
            "--stdio", "-p", "--", "run"}
    for part in cmd:
        if part in skip:
            continue
        if part.startswith("-"):
            continue
        if re.match(r"[A-Z]:\\|/", part):  # Windows/Unix absolute path
            continue
        if re.match(r"^\d", part):  # port number etc.
            continue
        return strip_version(part)
    return None


def load_existing_packages(root: Path) -> set[str]:
    """Return lowercased set of all package names already in the dataset."""
    known: set[str] = set()
    for yaml_file in (root / "case-studies").rglob("targets*.yaml"):
        try:
            data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not data or "targets" not in data:
            continue
        for target in data["targets"]:
            pkg = extract_pkg_from_cmd(target.get("cmd", []))
            if pkg:
                known.add(pkg.lower())
            name = target.get("name", "")
            if name:
                known.add(name.lower())
    return known


# ── npm API ───────────────────────────────────────────────────────────────────

async def npm_search_query(
    client: httpx.AsyncClient, query: str, max_results: int = 500
) -> list[dict]:
    """Paginate through npm search results for a single query."""
    results = []
    from_offset = 0
    while len(results) < max_results:
        batch = min(250, max_results - len(results))
        try:
            resp = await client.get(
                NPM_SEARCH_URL,
                params={"text": query, "size": batch, "from": from_offset},
                timeout=30.0,
            )
            resp.raise_for_status()
        except Exception as e:
            print(f"  [WARN] npm search {query!r} offset={from_offset}: {e}", file=sys.stderr)
            break
        objects = resp.json().get("objects", [])
        results.extend(objects)
        if len(objects) < batch:
            break
        from_offset += len(objects)
    return results


async def npm_weekly_downloads(client: httpx.AsyncClient, pkg: str) -> int:
    """Fetch weekly download count for a package."""
    try:
        resp = await client.get(f"{NPM_DOWNLOADS_URL}/{pkg}", timeout=15.0)
        if resp.status_code == 200:
            return resp.json().get("downloads", 0)
    except Exception:
        pass
    return 0


async def npm_get_bin(client: httpx.AsyncClient, pkg: str) -> Optional[str]:
    """
    Fetch package metadata and return the primary bin name if it differs
    from the package name. Returns None if cannot determine.
    """
    try:
        encoded = pkg.replace("/", "%2F")
        resp = await client.get(f"{NPM_REGISTRY_URL}/{encoded}/latest", timeout=15.0)
        if resp.status_code != 200:
            return None
        data = resp.json()
        bin_field = data.get("bin", {})
        if isinstance(bin_field, dict) and bin_field:
            return next(iter(bin_field))
        return None
    except Exception:
        return None


# ── Filtering / classification ────────────────────────────────────────────────

def is_mcp_server_candidate(pkg_obj: dict) -> bool:
    """
    Return True if this npm package looks like an MCP server (not a client,
    SDK, proxy, or unrelated package that happens to use 'mcp' in the name).
    """
    info = pkg_obj.get("package", {})
    name: str = info.get("name", "").lower()
    desc: str = info.get("description", "").lower()
    kws: list[str] = [k.lower() for k in info.get("keywords", [])]
    combined = f"{name} {desc} {' '.join(kws)}"

    # Must contain 'mcp'
    if "mcp" not in combined:
        return False

    # Exclude obvious non-servers
    exclusions = [
        # Python/Node client libraries
        "python client", "node client", "client library", "client sdk",
        # Inspector / browser tool
        "inspector", "playground", "studio", "debugger",
        # Framework / scaffolding
        "framework", "boilerplate", "template", "starter kit", "scaffold",
        "create-mcp", "create mcp",
        # Types / stubs
        "@types/", "typescript types", "type definitions",
        # Proxy / gateway (not a server itself)
        "mcp proxy", "mcp gateway",
        # Telemetry / instrumentation wrapper (not a server itself)
        "analytics wrapper", "telemetry wrapper", "instruments mcp",
        "observability wrapper", "monitoring wrapper",
        # Test utilities
        "test util", "testing tool", "mock server",
    ]
    if any(e in combined for e in exclusions):
        return False

    # Name-based exclusions
    name_exc = ["client", "sdk", "inspector", "types", "typings",
                "playground", "proxy", "gateway", "create-"]
    if any(n in name for n in name_exc):
        return False

    # Must look like a server
    server_signals = ["mcp-server", "-mcp", "mcp-", "server", "tool"]
    return any(s in combined for s in server_signals)


def estimate_auth(pkg_obj: dict) -> str:
    """
    Heuristic: 'likely-noauth' | 'maybe-auth' | 'likely-auth'
    Based on package name, description, and keywords.
    """
    info = pkg_obj.get("package", {})
    name: str = info.get("name", "").lower()
    desc: str = info.get("description", "").lower()
    kws: list[str] = [k.lower() for k in info.get("keywords", [])]
    combined = f"{name} {desc} {' '.join(kws)}"

    # Explicit no-auth statement wins immediately
    if any(p in combined for p in ["no api key", "no auth", "no authentication", "without api key"]):
        return "likely-noauth"

    # Explicit auth required
    if any(p in combined for p in ["api key required", "requires api key", "requires token",
                                    "authentication required", "api key needed"]):
        return "likely-auth"

    auth_hits = sum(1 for s in AUTH_SIGNALS if s in combined)
    noauth_hits = sum(1 for s in NOAUTH_SIGNALS if s in combined)

    # Explicit auth signal in description
    if "api key" in combined and "optional" not in combined:
        return "likely-auth"
    if "token" in combined and "optional" not in combined and "access token" not in desc[:50]:
        auth_hits += 1

    # Any auth keyword present and not outweighed by noauth → likely-auth
    # (e.g. @salesforce/mcp, @azure-devops/mcp, @gongrzhe/server-gmail-autoauth-mcp)
    if auth_hits >= 1 and auth_hits >= noauth_hits:
        return "likely-auth"
    if noauth_hits > auth_hits:
        return "likely-noauth"

    # Local tool heuristic
    local_kws = ["local", "file", "filesystem", "analysis", "linter", "format",
                 "documentation", "docs", "sqlite", "database", "duckdb"]
    if any(k in name or k in desc for k in local_kws):
        return "likely-noauth"

    return "maybe-auth"


# ── Output formatting ─────────────────────────────────────────────────────────

def build_target_entry(
    pkg_obj: dict,
    downloads: int,
    auth_est: str,
    tier: str,
    include_notes_metadata: bool = True,
) -> tuple[dict, str]:
    """
    Return (entry_dict, comment_line) for writing to YAML.
    entry_dict follows the standard corvus tracking format.
    """
    info = pkg_obj.get("package", {})
    npm_name: str = info.get("name", "")
    desc: str = info.get("description", "")
    version: str = info.get("version", "")

    # Derive a clean short name for the `name` field
    scope_match = re.match(r"^@([^/]+)/(.+)$", npm_name)
    if scope_match:
        scope_slug, pkg_part = scope_match.group(1), scope_match.group(2)
    else:
        scope_slug, pkg_part = "", npm_name

    clean = re.sub(r"[-_]?(mcp[-_]?server|mcp|server)$", "", pkg_part).strip("-_")

    # If cleaned name is too short/generic/empty, use scope for uniqueness
    GENERIC = {"ai", "mcp", "api", "server", "tool", "core", "base", "sdk", "plugin"}
    if (not clean or len(clean) <= 2 or clean in GENERIC) and scope_slug:
        if clean and clean not in {"mcp", "server", ""}:
            clean = f"{scope_slug}-{clean}"
        else:
            clean = scope_slug

    clean = clean or npm_name.replace("/", "-").replace("@", "")

    cmd = ["npx", "-y", f"{npm_name}@latest"]

    notes_parts = [f"{desc[:100]}" if desc else ""]
    if include_notes_metadata:
        notes_parts.append(f"discover: {downloads:,}/wk, auth_est={auth_est}, v{version}")

    entry = {
        "name": clean,
        "tier": tier,
        "transport": "stdio",
        "cmd": cmd,
        "status": "pending",
        "notes": ". ".join(p for p in notes_parts if p).rstrip("."),
    }

    comment = f"# {downloads:,}/wk  [{auth_est}]  {npm_name}"
    if desc:
        comment += f" — {desc[:70]}"
    return entry, comment


def write_candidates_yaml(
    candidates: list[tuple[dict, int, str]],
    output_path: Path,
    tier: str,
    existing_count: int,
    skipped_auth: int,
    skipped_dl: int,
    min_downloads: int,
) -> None:
    """Write candidates to a commented YAML file."""
    today = date.today().isoformat()
    lines = [
        f"# Auto-discovered MCP candidates — {today}",
        f"# REQUIRES MANUAL REVIEW — auth_est is heuristic only",
        f"# Run: python scripts/discover.py --help",
        "#",
        f"# Total candidates: {len(candidates)}",
        f"# Cross-referenced against: {existing_count} known packages",
        f"# Filtered out — likely requires auth: {skipped_auth}",
        f"# Filtered out — low downloads (<{min_downloads}/wk): {skipped_dl}",
        "",
    ]

    # meta block
    meta = {
        "meta": {
            "case_study": tier,
            "description": f"OWASP MCP Ecosystem Audit — {tier} auto-discovered ({today})",
            "corvus_version": "1.1.0",
            "strategy": (
                f"npm auto-discovery via discover.py. "
                f"Filters: >{min_downloads} dl/wk, likely-noauth heuristic. "
                f"Cross-referenced against CS01-CS04 ({existing_count} known packages). "
                f"Requires manual review — remove 'status: pending' or set 'status: skip' before scanning."
            ),
            "discover_date": today,
        }
    }
    lines.append(yaml.dump(meta, default_flow_style=False, allow_unicode=True, sort_keys=False).rstrip())
    lines.append("targets:")
    lines.append("")

    for pkg_obj, downloads, auth_est in candidates:
        entry, comment = build_target_entry(pkg_obj, downloads, auth_est, tier)
        lines.append(comment)
        # Dump entry as a YAML list item
        entry_yaml = yaml.dump([entry], default_flow_style=False, allow_unicode=True, sort_keys=False)
        # yaml.dump(['item'] outputs '- key: val\n', which is what we want
        lines.append(entry_yaml.rstrip())
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def write_skipped_report(
    skipped_auth: list[tuple[str, int, str]],
    skipped_dl: list[tuple[str, int]],
    output_path: Path,
    min_downloads: int,
) -> None:
    """Write the skipped packages report."""
    lines = ["# Discover skipped report", ""]

    lines.append(f"## Likely requires auth ({len(skipped_auth)} packages)")
    lines.append("")
    for name, dl, reason in sorted(skipped_auth, key=lambda x: -x[1]):
        lines.append(f"{dl:8,}/wk  {reason:<14}  {name}")

    lines.append("")
    lines.append(f"## Low downloads <{min_downloads}/wk ({len(skipped_dl)} packages)")
    lines.append("")
    for name, dl in sorted(skipped_dl, key=lambda x: -x[1]):
        lines.append(f"{dl:8,}/wk  {name}")

    output_path.write_text("\n".join(lines), encoding="utf-8")


# ── Main ──────────────────────────────────────────────────────────────────────

async def run(args: argparse.Namespace) -> None:
    today = date.today().isoformat()
    tier = args.tier

    output_dir = CORVUS_ROOT / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load existing dataset
    print("[discover] Loading existing dataset...", file=sys.stderr)
    existing = load_existing_packages(CORVUS_ROOT)
    print(f"[discover] {len(existing)} known packages (CS01–CS04)", file=sys.stderr)

    # Search npm
    print("\n[discover] Searching npm registry...", file=sys.stderr)
    seen_names: set[str] = set()
    all_pkgs: list[dict] = []

    async with httpx.AsyncClient() as client:
        for query in NPM_QUERIES:
            print(f"  → query: {query!r}", file=sys.stderr)
            results = await npm_search_query(client, query, max_results=args.max_results)
            added = 0
            for p in results:
                n = p.get("package", {}).get("name", "")
                if n and n not in seen_names:
                    seen_names.add(n)
                    all_pkgs.append(p)
                    added += 1
            print(f"     {len(results)} results, {added} new unique", file=sys.stderr)

        print(f"\n[discover] {len(all_pkgs)} unique packages total", file=sys.stderr)

        # Filter to MCP servers
        server_pkgs = [p for p in all_pkgs if is_mcp_server_candidate(p)]
        print(f"[discover] {len(server_pkgs)} look like MCP servers", file=sys.stderr)

        # Exclude existing
        new_pkgs = []
        for p in server_pkgs:
            n = p.get("package", {}).get("name", "").lower()
            clean = re.sub(r"^@[^/]+/", "", n)
            if n not in existing and clean not in existing:
                new_pkgs.append(p)
        print(f"[discover] {len(new_pkgs)} not in existing dataset", file=sys.stderr)

        # Fetch download counts in parallel batches
        print(f"\n[discover] Fetching download stats ({len(new_pkgs)} packages)...", file=sys.stderr)
        download_cache: dict[str, int] = {}
        sem = asyncio.Semaphore(20)

        async def fetch_dl(p: dict) -> None:
            name = p.get("package", {}).get("name", "")
            async with sem:
                dl = await npm_weekly_downloads(client, name)
            download_cache[name] = dl

        batch_size = 50
        for i in range(0, len(new_pkgs), batch_size):
            batch = new_pkgs[i : i + batch_size]
            await asyncio.gather(*[fetch_dl(p) for p in batch])
            print(f"  {min(i + batch_size, len(new_pkgs))}/{len(new_pkgs)}", file=sys.stderr)

        # Apply filters and classify
        include_levels: set[str] = {"likely-noauth"}
        if args.include_maybe_auth:
            include_levels.add("maybe-auth")

        candidates: list[tuple[dict, int, str]] = []
        skipped_auth: list[tuple[str, int, str]] = []
        skipped_dl: list[tuple[str, int]] = []

        for p in new_pkgs:
            name = p.get("package", {}).get("name", "")
            dl = download_cache.get(name, 0)
            auth_est = estimate_auth(p)

            if dl < args.min_downloads:
                skipped_dl.append((name, dl))
                continue
            if auth_est not in include_levels:
                skipped_auth.append((name, dl, auth_est))
                continue

            candidates.append((p, dl, auth_est))

        # Sort by downloads desc, cap at top_n
        candidates.sort(key=lambda x: x[1], reverse=True)
        if args.top_n:
            candidates = candidates[: args.top_n]

    # Report
    print(f"\n[discover] ─── Summary ───────────────────────────────────")
    print(f"  Candidates (noauth, >{args.min_downloads}/wk): {len(candidates)}")
    print(f"  Skipped auth signals:                        {len(skipped_auth)}")
    print(f"  Skipped low downloads:                       {len(skipped_dl)}")

    if candidates:
        print(f"\n[discover] Top {min(20, len(candidates))} candidates:")
        for pkg_obj, dl, auth_est in candidates[:20]:
            n = pkg_obj.get("package", {}).get("name", "")
            d = pkg_obj.get("package", {}).get("description", "")[:60]
            print(f"  {dl:7,}/wk  [{auth_est:<14}]  {n}")
            if d:
                print(f"             {d}")

    # Write output
    out_yaml = output_dir / f"candidates-{today}.yaml"
    out_skip = output_dir / f"skipped-{today}.txt"

    write_candidates_yaml(
        candidates, out_yaml, tier,
        existing_count=len(existing),
        skipped_auth=len(skipped_auth),
        skipped_dl=len(skipped_dl),
        min_downloads=args.min_downloads,
    )
    write_skipped_report(skipped_auth, skipped_dl, out_skip, args.min_downloads)

    print(f"\n[discover] Output:  {out_yaml}")
    print(f"[discover] Skipped: {out_skip}")
    print(f"\n[discover] Next: review {out_yaml}, remove status:pending, run:")
    print(f"           corvus batch {out_yaml}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Discover new MCP server candidates from npm registry",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--min-downloads", type=int, default=200, metavar="N",
        help="Minimum weekly downloads to include (default: 200)"
    )
    parser.add_argument(
        "--include-maybe-auth", action="store_true",
        help="Include 'maybe-auth' candidates (default: only 'likely-noauth')"
    )
    parser.add_argument(
        "--top-n", type=int, default=150, metavar="N",
        help="Max candidates in output (default: 150)"
    )
    parser.add_argument(
        "--max-results", type=int, default=500, metavar="N",
        help="Max npm results per query (default: 500)"
    )
    parser.add_argument(
        "--output-dir", default="scripts/discover-output", metavar="DIR",
        help="Output directory relative to corvus root (default: scripts/discover-output)"
    )
    parser.add_argument(
        "--tier", default="CS05-DISCOVER", metavar="TIER",
        help="Tier label in output YAML (default: CS05-DISCOVER)"
    )
    args = parser.parse_args()

    try:
        import httpx  # noqa: F401
    except ImportError:
        print("[error] httpx not installed. Run: pip install httpx", file=sys.stderr)
        sys.exit(1)
    try:
        import yaml  # noqa: F401
    except ImportError:
        print("[error] pyyaml not installed. Run: pip install pyyaml", file=sys.stderr)
        sys.exit(1)

    asyncio.run(run(args))


if __name__ == "__main__":
    main()

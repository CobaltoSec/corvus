#!/usr/bin/env python3
"""CS02 Scraper — discovers batchable MCP servers from npm registry.

Sources:
  - npm search API (multiple queries, deduped)
  - Optional Smithery.ai registry API

Outputs:
  - candidates.yaml     — full ranked list with metadata
  - tier-d-snippet.yaml — ready-to-paste entries for targets-master.yaml

Usage:
  python scraper.py                   # full scrape, min 100 weekly downloads
  python scraper.py --min-downloads 50
  python scraper.py --dry-run         # show counts only, no output files
"""
import argparse
import time
from pathlib import Path

import httpx
import yaml

HERE = Path(__file__).parent
MASTER_YAML = HERE.parent / "cs01-mcp-ecosystem" / "targets-master.yaml"
CANDIDATES_OUT = HERE / "candidates.yaml"
SNIPPET_OUT = HERE / "tier-d-snippet.yaml"

NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
NPM_REGISTRY = "https://registry.npmjs.org/{package}"
NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week/{package}"
SMITHERY_API = "https://registry.smithery.ai/servers?pageSize=100&page={page}"

SEARCH_QUERIES = [
    "mcp-server keywords:mcp",
    "mcp-server keywords:modelcontextprotocol",
    "model context protocol server",
    "keywords:mcp-server",
]

# Known auth-required or broken packages (skip outright)
KNOWN_SKIP = {
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-aws-kb-retrieval",
    "@modelcontextprotocol/server-slack",
    "@notionhq/notion-mcp-server",
    "tavily-mcp",
    "exa-mcp-server",
    "@modelcontextprotocol/server-gitlab",
    "@jakenuts/mcp-cli-exec",
    "filesystem-mcp-server",
    "@agent-infra/mcp-server-filesystem",
    "@contextware/mcp-scan",
    # client libraries / SDKs — not servers
    "@modelcontextprotocol/sdk",
    "mcp",
    "@anthropic-ai/sdk",
    "fastmcp",
    # evals / benchmarks
    "mcp-evals",
}

# Name substrings that indicate platform-specific binaries (never batchable directly)
PLATFORM_BINARY_PATTERNS = [
    "-win32-x64", "-linux-x64", "-linux-arm64",
    "-darwin-arm64", "-darwin-x64", "-darwin-universal",
]

# Service names that almost always require auth/account — skip by package name
AUTH_SERVICE_NAMES = [
    "azure", "sentry", "airtable", "clickup", "shopify", "ms-365",
    "office365", "office-365", "jira", "confluence", "salesforce",
    "hubspot", "stripe", "twilio", "sendgrid", "datadog", "pagerduty",
    "snowflake", "databricks", "pinecone", "weaviate", "upstash",
    "mongodb", "redis", "elasticsearch", "cassandra", "dynamodb",
    "firebase", "supabase", "neon", "planetscale",
    "kubernetes", "k8s", "searxng", "grafana", "prometheus",
    "linear", "asana", "monday", "zendesk", "intercom",
    "github-enterprise", "gitlab", "bitbucket", "notion",
    "openai", "gemini", "anthropic", "mistral", "cohere",
]

# Description/keyword patterns that suggest auth requirement
AUTH_PATTERNS = [
    "api_key", "api key", "apikey", "_token", "secret",
    "oauth", "credentials", "requires.*key", "set.*api",
    "huggingface", "requires an api",
]

# Packages that are clearly clients, SDKs or dev tools — not scannable servers
NON_SERVER_PATTERNS = [
    "client library", "sdk for", "playground", "inspector", "dashboard",
    "proxy server", "gateway", "scaffold", "template",
    "boilerplate", "starter kit", "demo app",
    "mock server", "stub", "fixture",
    "eslint", "prettier", "typescript types",
    "eval framework", "benchmark", "test suite",
]


def load_existing_targets() -> set[str]:
    """Load package names already in targets-master.yaml."""
    if not MASTER_YAML.exists():
        return set()
    with MASTER_YAML.open() as f:
        data = yaml.safe_load(f)
    existing = set()
    for t in data.get("targets", []):
        # extract package name from cmd array
        cmd = t.get("cmd", [])
        for i, part in enumerate(cmd):
            # npx -y <package> or uvx <package>
            if part in ("-y",):
                if i + 1 < len(cmd):
                    existing.add(cmd[i + 1])
            elif part in ("npx", "uvx", "node"):
                continue
            elif part.startswith("@") or (part and part[0].isalpha() and "/" not in part):
                existing.add(part)
                break
        # also add by name field
        existing.add(t.get("name", ""))
    return existing


def search_npm(client: httpx.Client, query: str, size: int = 250) -> list[dict]:
    """Search npm registry, return list of package objects."""
    results = []
    try:
        r = client.get(NPM_SEARCH, params={"text": query, "size": size}, timeout=15)
        r.raise_for_status()
        data = r.json()
        results = data.get("objects", [])
    except Exception as e:
        print(f"  [warn] npm search '{query}': {e}")
    return results


def fetch_smithery(client: httpx.Client, pages: int = 5) -> list[dict]:
    """Try Smithery registry API for additional servers."""
    smithery_pkgs = []
    for page in range(1, pages + 1):
        try:
            r = client.get(SMITHERY_API.format(page=page), timeout=10)
            if r.status_code == 200:
                data = r.json()
                servers = data.get("servers", [])
                if not servers:
                    break
                smithery_pkgs.extend(servers)
                time.sleep(0.3)
            else:
                break
        except Exception:
            break
    return smithery_pkgs


def get_pkg_details(client: httpx.Client, name: str) -> dict | None:
    """Fetch package.json from npm registry."""
    try:
        encoded = name.replace("/", "%2F")
        r = client.get(NPM_REGISTRY.format(package=encoded), timeout=10)
        if r.status_code != 200:
            return None
        data = r.json()
        latest_ver = data.get("dist-tags", {}).get("latest", "")
        latest = data.get("versions", {}).get(latest_ver, {})
        return {
            "name": name,
            "version": latest_ver,
            "description": data.get("description", ""),
            "keywords": data.get("keywords", []),
            "bin": latest.get("bin", {}),
            "main": latest.get("main", ""),
            "scripts": latest.get("scripts", {}),
        }
    except Exception:
        return None


def get_weekly_downloads(client: httpx.Client, name: str) -> int:
    """Fetch last-week download count from npm."""
    try:
        encoded = name.replace("/", "%2F")
        r = client.get(NPM_DOWNLOADS.format(package=encoded), timeout=10)
        if r.status_code == 200:
            return r.json().get("downloads", 0)
    except Exception:
        pass
    return 0


def is_platform_binary(name: str) -> bool:
    """True if this is a platform-specific binary package (not directly invokable via npx)."""
    name_lower = name.lower()
    return any(p in name_lower for p in PLATFORM_BINARY_PATTERNS)


def is_likely_auth_required(name: str, pkg: dict) -> bool:
    """Heuristic: does this package likely require an API key/account to run?"""
    name_lower = name.lower()
    # Check service name patterns in package name
    if any(svc in name_lower for svc in AUTH_SERVICE_NAMES):
        return True
    # Check description/keywords
    text = (pkg.get("description", "") + " " + " ".join(pkg.get("keywords", []))).lower()
    return any(p in text for p in AUTH_PATTERNS)


LIB_NAME_PATTERNS = [
    "-sdk", "-ts-core", "-transports", "-transport",
    "-generator", "-inspector", "-playground", "-types",
    "-client", "-utils", "-helpers",
]


def is_likely_not_server(name: str, pkg: dict) -> bool:
    """Heuristic: is this a client/SDK/tool rather than a scannable server?"""
    name_lower = name.lower()
    # Skip by package name suffix patterns
    if any(p in name_lower for p in LIB_NAME_PATTERNS):
        return True
    text = (name + " " + pkg.get("description", "") + " " + " ".join(pkg.get("keywords", []))).lower()
    # Must have mcp-related keywords to be a server
    if not any(k in text for k in ["mcp", "model context protocol", "modelcontextprotocol"]):
        return True
    # Skip non-server patterns
    return any(p in text for p in NON_SERVER_PATTERNS)


def is_batchable(pkg: dict) -> bool:
    """True if package can be run via `npx -y <name>` without setup."""
    # Has a bin entry → npx can invoke it
    if pkg.get("bin"):
        return True
    # Has a main script that could work
    if pkg.get("main"):
        return True
    return False


def make_snippet_entry(pkg: dict, downloads: int) -> dict:
    """Build a targets-master.yaml entry for this package."""
    name = pkg["name"]
    # Derive a short display name
    display = name.split("/")[-1] if "/" in name else name
    return {
        "name": display,
        "tier": "D",
        "transport": "stdio",
        "cmd": ["npx", "-y", name],
        "status": "pending",
        "notes": f"{pkg.get('description', '').strip()}. {downloads:,} weekly downloads.",
    }


def main():
    parser = argparse.ArgumentParser(description="CS02 MCP server scraper")
    parser.add_argument("--min-downloads", type=int, default=500)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--pages-smithery", type=int, default=5)
    args = parser.parse_args()

    existing = load_existing_targets()
    print(f"[*] Existing targets in master YAML: {len(existing)}")

    seen: dict[str, dict] = {}  # name → npm object

    with httpx.Client(follow_redirects=True) as client:
        # ── 1. npm search ──────────────────────────────────────────────────────
        print("\n[*] Querying npm registry...")
        for query in SEARCH_QUERIES:
            print(f"    query: {query!r}")
            results = search_npm(client, query)
            for obj in results:
                pkg_name = obj.get("package", {}).get("name", "")
                if pkg_name and pkg_name not in seen:
                    seen[pkg_name] = obj
            time.sleep(0.5)
        print(f"    → {len(seen)} unique packages from npm search")

        # ── 2. Smithery ────────────────────────────────────────────────────────
        print("\n[*] Trying Smithery registry...")
        smithery_data = fetch_smithery(client, pages=args.pages_smithery)
        smithery_npm_names = set()
        for s in smithery_data:
            # Smithery entries have qualifiedName like "@owner/repo" or npm package name
            npm_name = s.get("qualifiedName", "") or s.get("name", "")
            if npm_name and npm_name not in seen:
                smithery_npm_names.add(npm_name)
        if smithery_npm_names:
            print(f"    → {len(smithery_npm_names)} additional from Smithery")
            for name in smithery_npm_names:
                seen[name] = {"package": {"name": name, "description": ""}}
        else:
            print("    → Smithery API not available or empty")

        # ── 3. Filter pass 1 — known skip + non-servers ────────────────────────
        candidates_pass1 = []
        for name, obj in seen.items():
            if name in KNOWN_SKIP:
                continue
            if name in existing:
                continue
            desc = obj.get("package", {}).get("description", "")
            if is_likely_not_server(name, {"description": desc, "keywords": []}):
                continue
            candidates_pass1.append(name)

        print(f"\n[*] After basic filter: {len(candidates_pass1)} candidates")
        print("[*] Fetching package details + download counts...")

        # ── 4. Fetch details + downloads ───────────────────────────────────────
        candidates_full = []
        pkg_cache: dict[str, dict] = {}
        for i, name in enumerate(candidates_pass1):
            if i % 20 == 0:
                print(f"    {i}/{len(candidates_pass1)}...")
            if is_platform_binary(name):
                continue
            pkg = get_pkg_details(client, name)
            if pkg is None:
                continue
            downloads = get_weekly_downloads(client, name)
            time.sleep(0.15)  # polite rate limiting

            # Filter pass 2
            if downloads < args.min_downloads:
                continue
            if is_likely_auth_required(name, pkg):
                continue
            if not is_batchable(pkg):
                continue

            pkg_cache[name] = pkg
            candidates_full.append({
                "name": name,
                "version": pkg["version"],
                "description": pkg.get("description", ""),
                "keywords": pkg.get("keywords", []),
                "weekly_downloads": downloads,
                "has_bin": bool(pkg.get("bin")),
                "auth_required": False,
            })

        # Sort by weekly downloads descending
        candidates_full.sort(key=lambda x: x["weekly_downloads"], reverse=True)

        print(f"\n[*] Final candidates: {len(candidates_full)}")
        for c in candidates_full[:20]:
            print(f"    {c['weekly_downloads']:>8,}  {c['name']}")
        if len(candidates_full) > 20:
            print(f"    ... and {len(candidates_full) - 20} more")

        if args.dry_run:
            print("\n[dry-run] No files written.")
            return

        # ── 5. Write outputs ───────────────────────────────────────────────────
        CANDIDATES_OUT.parent.mkdir(parents=True, exist_ok=True)

        with CANDIDATES_OUT.open("w") as f:
            yaml.dump(
                {"meta": {"min_downloads": args.min_downloads, "total": len(candidates_full)},
                 "candidates": candidates_full},
                f, default_flow_style=False, allow_unicode=True,
            )
        print(f"\n[+] candidates.yaml → {CANDIDATES_OUT}")

        # Build tier-D snippet (use cached pkg details — no re-fetch)
        snippet_entries = []
        for c in candidates_full:
            pkg_detail = pkg_cache.get(c["name"], {"bin": {}})
            entry = make_snippet_entry(
                {"name": c["name"], "description": c["description"], "bin": pkg_detail.get("bin", {})},
                c["weekly_downloads"],
            )
            snippet_entries.append(entry)

        with SNIPPET_OUT.open("w") as f:
            yaml.dump(snippet_entries, f, default_flow_style=False, allow_unicode=True)
        print(f"[+] tier-d-snippet.yaml → {SNIPPET_OUT}")
        print(f"\n[✓] Done. {len(candidates_full)} candidates ready for review.")


if __name__ == "__main__":
    main()

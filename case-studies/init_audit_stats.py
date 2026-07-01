"""init_audit_stats.py — aggregate init_audit findings across all CS01+CS02 scan results.

Usage:
    python case-studies/init_audit_stats.py

Outputs:
    - Protocol version downgrade acceptance rate
    - Per-server breakdown
    - Summary suitable for CFP/paper citation
"""
from __future__ import annotations

import json
import os
from pathlib import Path

_BASE_DIRS = [
    Path(__file__).parent / "cs01-mcp-ecosystem" / "batch-scans",
    Path(__file__).parent / "cs02-mcp-ecosystem" / "batch-scans",
]


def _latest_reports() -> dict[str, Path]:
    """Return {server_name: latest_report_json} across all batch scan runs."""
    servers: dict[str, Path] = {}
    for base in _BASE_DIRS:
        if not base.exists():
            continue
        for batch in sorted(base.iterdir()):
            if not batch.is_dir():
                continue
            for srv_dir in batch.iterdir():
                rjson = srv_dir / "report.json"
                if rjson.exists():
                    servers[srv_dir.name] = rjson  # latest run wins
    return servers


def run() -> None:
    servers = _latest_reports()
    total = len(servers)

    init_audit_run: list[str] = []
    downgrade_accepted: list[str] = []
    serverinfo_injection: list[str] = []

    for name, path in servers.items():
        with open(path) as f:
            d = json.load(f)

        mods = d.get("modules_run", [])
        if "init-audit" not in mods:
            continue
        init_audit_run.append(name)

        findings = d.get("findings", [])
        mcp07 = [f for f in findings if f.get("owasp_category") == "MCP07"]
        for finding in mcp07:
            title = finding.get("title", "")
            if "downgrade" in title.lower():
                downgrade_accepted.append(name)
                break
        for finding in mcp07:
            title = finding.get("title", "")
            if "injection" in title.lower() or "control" in title.lower():
                serverinfo_injection.append(name)
                break

    scanned = len(init_audit_run)
    n_dg = len(downgrade_accepted)
    n_inj = len(serverinfo_injection)

    print("=" * 60)
    print("init_audit aggregate stats — CS01 + CS02")
    print("=" * 60)
    print(f"Total servers with scan results : {total}")
    print(f"Servers with init-audit run     : {scanned}")
    print()
    print(f"Protocol version downgrade      : {n_dg}/{scanned} ({n_dg/scanned*100:.1f}%)")
    print(f"serverInfo injection chars      : {n_inj}/{scanned} ({n_inj/scanned*100:.1f}%)")
    print()
    print("Downgrade-accepting servers:")
    for s in sorted(downgrade_accepted):
        print(f"  - {s}")
    if serverinfo_injection:
        print("serverInfo injection servers:")
        for s in sorted(serverinfo_injection):
            print(f"  - {s}")
    print()
    print("CFP citation format:")
    print(f"  «{n_dg} of {scanned} audited MCP servers ({n_dg/scanned*100:.0f}%) accepted "
          f"protocol version downgrade requests, indicating systemic lack of "
          f"protocolVersion validation across the ecosystem.»")


if __name__ == "__main__":
    run()

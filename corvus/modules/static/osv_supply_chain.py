from __future__ import annotations

from typing import Any

import httpx

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport
from .supply_chain import _extract_npm_package
from .supply_chain_python import _extract_python_package

_OSV_API = "https://api.osv.dev/v1/query"

_OSV_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
}


async def _query_osv(package_name: str, ecosystem: str) -> list[dict[str, Any]]:
    """Query OSV.dev for known vulnerabilities. Returns empty list on any error."""
    payload = {"package": {"name": package_name, "ecosystem": ecosystem}}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(_OSV_API, json=payload)
            if resp.status_code != 200:
                return []
            return resp.json().get("vulns", [])
    except Exception:
        return []


def _parse_osv_vulns(
    vulns: list[dict[str, Any]], package_name: str, ecosystem: str
) -> list[Finding]:
    findings: list[Finding] = []

    for vuln in vulns:
        vuln_id = vuln.get("id", "?")
        summary = vuln.get("summary", "")
        aliases = vuln.get("aliases", [])

        cve_ids = [a for a in aliases if isinstance(a, str) and a.upper().startswith("CVE-")]
        cve_str = ", ".join(cve_ids) if cve_ids else "no CVE assigned"

        db_sev = (vuln.get("database_specific") or {}).get("severity", "").lower()
        severity = _OSV_SEVERITY_MAP.get(db_sev, Severity.HIGH if cve_ids else Severity.MEDIUM)
        confidence = 90 if cve_ids else 65

        ranges_parts: list[str] = []
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "introduced" in event:
                        ranges_parts.append(f"introduced:{event['introduced']}")
                    if "fixed" in event:
                        ranges_parts.append(f"fixed:{event['fixed']}")

        evidence = f"{package_name} ({ecosystem}) — {vuln_id} ({cve_str})"
        if ranges_parts:
            evidence += " — " + " ".join(ranges_parts)

        findings.append(Finding(
            owasp_category=OWASPCategory.MCP04_SUPPLY_CHAIN,
            severity=severity,
            title=f"Supply Chain — OSV.dev {vuln_id} affects '{package_name}' ({cve_str})",
            description=(
                f"OSV.dev advisory {vuln_id}: {summary}\n"
                f"Package '{package_name}' (ecosystem: {ecosystem}) has a known "
                f"{severity.value} vulnerability. Detected via OSV.dev API — no local tooling required."
            ),
            tool_name=None,
            evidence=evidence,
            remediation=f"See https://osv.dev/{vuln_id} and update '{package_name}' to a patched version.",
            confidence=confidence,
        ))

    return findings


class OsvSupplyChainModule(ScanModule):
    owasp_id = "MCP04"
    category = "Supply Chain Attacks"
    name = "osv-supply-chain"
    description = (
        "Static check: queries OSV.dev API for known vulnerabilities in the target package. "
        "Works for stdio (npm/Python) and HTTP transports. No local tooling required."
    )
    is_static = True

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        package: str | None = None
        ecosystem: str | None = None

        if session.transport == "stdio":
            npm_pkg = _extract_npm_package(session.target)
            if npm_pkg:
                package, ecosystem = npm_pkg, "npm"
            else:
                py_pkg = _extract_python_package(session.target)
                if py_pkg:
                    package, ecosystem = py_pkg, "PyPI"

        elif session.transport == "http" and surface is not None and surface.server_name:
            package = surface.server_name
            ecosystem = "npm"

        if not package or not ecosystem:
            return []

        vulns = await _query_osv(package, ecosystem)

        # For HTTP transport, if npm yields nothing, try PyPI
        if not vulns and session.transport == "http" and ecosystem == "npm":
            vulns = await _query_osv(package, "PyPI")
            if vulns:
                ecosystem = "PyPI"

        return _parse_osv_vulns(vulns, package, ecosystem)

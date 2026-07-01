from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

import httpx

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

_GH_ADVISORY_API = "https://api.github.com/advisories"
_MAX_PACKAGES = 30


def _find_package_json(target: str) -> Path | None:
    """Try to find package.json near the stdio target command."""
    try:
        parts = shlex.split(target, posix=False)
    except ValueError:
        parts = target.split()

    for part in parts:
        p = Path(part)
        if p.suffix in (".js", ".mjs", ".cjs"):
            candidate = p.parent / "package.json"
            if candidate.exists():
                return candidate
        if p.is_dir():
            candidate = p / "package.json"
            if candidate.exists():
                return candidate

    cwd_pkg = Path.cwd() / "package.json"
    if cwd_pkg.exists():
        return cwd_pkg

    return None


def _read_deps(pkg_json: Path) -> list[str]:
    """Extract dependency names from package.json (dependencies + devDependencies)."""
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except Exception:
        return []
    deps: list[str] = []
    for key in ("dependencies", "devDependencies"):
        deps.extend(data.get(key, {}).keys())
    return deps[:_MAX_PACKAGES]


async def _query_gh_advisories(pkg_name: str) -> list[dict[str, Any]]:
    """Query GitHub Security Advisories for an npm package. Returns [] on any error."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                _GH_ADVISORY_API,
                params={"ecosystem": "npm", "package": pkg_name, "per_page": "5"},
                headers={
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "corvus-scanner",
                },
            )
            if resp.status_code != 200:
                return []
            return resp.json() if isinstance(resp.json(), list) else []
    except Exception:
        return []


def _cvss_to_severity(cvss_score: float | None) -> Severity:
    if cvss_score is None:
        return Severity.INFO
    if cvss_score >= 9.0:
        return Severity.CRITICAL
    if cvss_score >= 7.0:
        return Severity.HIGH
    if cvss_score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _parse_advisory(advisory: dict[str, Any], pkg_name: str) -> Finding | None:
    ghsa_id = advisory.get("ghsa_id", "?")
    summary = advisory.get("summary", "")
    cve_ids = [c["value"] for c in advisory.get("cve_ids", []) if isinstance(c, dict)]
    cvss_score: float | None = None
    cvss_data = advisory.get("cvss")
    if isinstance(cvss_data, dict):
        score = cvss_data.get("score")
        if score is not None:
            try:
                cvss_score = float(score)
            except (TypeError, ValueError):
                pass

    severity = _cvss_to_severity(cvss_score)
    cve_str = ", ".join(cve_ids) if cve_ids else "no CVE assigned"
    evidence = f"{ghsa_id} ({cve_str})"
    if cvss_score is not None:
        evidence += f" — CVSS {cvss_score}"

    return Finding(
        owasp_category=OWASPCategory.MCP04_SUPPLY_CHAIN,
        severity=severity,
        title=f"GitHub Advisory — {ghsa_id} in {pkg_name}",
        description=(
            f"GitHub Security Advisory {ghsa_id}: {summary}\n"
            f"Package '{pkg_name}' (npm) has a known {severity.value} vulnerability."
        ),
        tool_name=None,
        evidence=evidence,
        remediation=f"See https://github.com/advisories/{ghsa_id} and update '{pkg_name}'.",
        confidence=90 if cve_ids else 70,
    )


class GitHubAdvisoryModule(ScanModule):
    owasp_id = "MCP04"
    category = "Supply Chain Attacks"
    name = "github-advisory"
    description = (
        "Static check: queries GitHub Security Advisories API for known vulnerabilities "
        "in npm dependencies found in package.json. Stdio targets only."
    )
    is_static = True

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        if session.transport != "stdio":
            return []

        pkg_json = _find_package_json(session.target)
        if pkg_json is None:
            return []

        deps = _read_deps(pkg_json)
        if not deps:
            return []

        findings: list[Finding] = []
        for pkg_name in deps:
            try:
                advisories = await _query_gh_advisories(pkg_name)
            except Exception:
                continue
            for advisory in advisories:
                finding = _parse_advisory(advisory, pkg_name)
                if finding is not None:
                    findings.append(finding)
        return findings

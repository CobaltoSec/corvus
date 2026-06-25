from __future__ import annotations

import asyncio
import json
import re
import shlex
import shutil
import tempfile
from pathlib import Path

_NPM = shutil.which("npm") or "npm"

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "moderate": Severity.MEDIUM,
}


def _extract_npm_package(target: str) -> str | None:
    """Extract npm package name from a stdio cmd string. Returns None if not npm."""
    try:
        parts = shlex.split(target, posix=False)
    except ValueError:
        return None

    for i, part in enumerate(parts):
        basename = Path(part).name.lower()
        if basename in ("npx", "npx.cmd", "npx.exe"):
            for candidate in parts[i + 1:]:
                if not candidate.startswith("-"):
                    return candidate
            break
        if basename in ("npm", "npm.cmd", "npm.exe") and i + 1 < len(parts) and parts[i + 1] in ("exec", "x"):
            for candidate in parts[i + 2:]:
                if candidate == "--":
                    continue
                if not candidate.startswith("-"):
                    return candidate
            break

    return None


async def _run_npm_audit(package: str) -> dict:
    """Install package lock-only in a temp dir and run npm audit --json."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg_json = Path(tmpdir) / "package.json"
        pkg_json.write_text(json.dumps({
            "name": "corvus-supply-probe",
            "version": "1.0.0",
            "dependencies": {package: "latest"},
        }))

        install = await asyncio.create_subprocess_exec(
            _NPM, "install", "--package-lock-only", "--no-fund", "--no-audit",
            cwd=tmpdir,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(install.wait(), timeout=60)
        except asyncio.TimeoutError:
            return {}

        audit = await asyncio.create_subprocess_exec(
            _NPM, "audit", "--json",
            cwd=tmpdir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(audit.communicate(), timeout=30)
        except asyncio.TimeoutError:
            return {}

    if not stdout:
        return {}
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {}


def _parse_audit(audit_json: dict, package: str) -> list[Finding]:
    findings: list[Finding] = []
    vulnerabilities = audit_json.get("vulnerabilities", {})

    for vuln_name, vuln in vulnerabilities.items():
        sev_str = vuln.get("severity", "").lower()
        severity = _SEVERITY_MAP.get(sev_str)
        if severity is None:
            continue

        via_list = vuln.get("via", [])

        # Cascade advisory: via contains only package-name strings (no advisory objects).
        # The package itself is not vulnerable — it just transitively depends on one that is.
        # The actual vulnerable dep appears as its own entry; skip the cascade wrapper.
        if via_list and all(isinstance(v, str) for v in via_list):
            continue

        # Extract CVE IDs from via entries
        cve_ids: list[str] = []
        for via in via_list:
            if not isinstance(via, dict):
                continue
            if "cve" in via:
                cve_ids.append(str(via["cve"]).upper())
            else:
                search = via.get("url", "") + " " + via.get("title", "")
                m = re.search(r"CVE-\d{4}-\d+", search, re.I)
                if m:
                    cve_ids.append(m.group(0).upper())

        cve_str = ", ".join(cve_ids) if cve_ids else "no CVE assigned"

        fix_version = ""
        fix = vuln.get("fixAvailable")
        if isinstance(fix, dict):
            fix_version = fix.get("version", "")

        evidence = f"{vuln_name}@{vuln.get('range', '?')} — {cve_str}"
        if fix_version:
            evidence += f" — fix: {fix_version}"

        findings.append(Finding(
            owasp_category=OWASPCategory.MCP04_SUPPLY_CHAIN,
            severity=severity,
            title=f"Supply Chain — '{vuln_name}' has {sev_str} vulnerability ({cve_str})",
            description=(
                f"Package '{vuln_name}' (dependency of '{package}') has a known {sev_str} "
                "vulnerability. Solo aplicable a servidores npm vía stdio. "
                "HTTP transport: no analizable."
            ),
            tool_name=None,
            evidence=evidence,
            remediation=(
                f"Update '{vuln_name}' to {fix_version}."
                if fix_version
                else f"Update '{vuln_name}' to a patched version."
            ),
            confidence=65 if cve_str == "no CVE assigned" else 90,
        ))

    return findings


class SupplyChainModule(ScanModule):
    owasp_id = "MCP04"
    category = "Supply Chain Attacks"
    name = "supply-chain"
    description = (
        "Pre-scan static check: extracts the npm package from a stdio cmd, "
        "runs npm audit, and reports known vulnerabilities. "
        "Only applicable to stdio transports with npx/npm commands."
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

        package = _extract_npm_package(session.target)
        if not package:
            return []

        audit_json = await _run_npm_audit(package)
        return _parse_audit(audit_json, package)

from __future__ import annotations

import asyncio
import json
import shlex
import shutil
import tempfile
from pathlib import Path

_PIP_AUDIT = shutil.which("pip-audit") or "pip-audit"

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport


def _extract_python_package(target: str) -> str | None:
    """Extract Python package from uvx/uv stdio commands. Returns None if not Python."""
    try:
        parts = shlex.split(target, posix=False)
    except ValueError:
        return None

    for i, part in enumerate(parts):
        basename = Path(part).name.lower()
        rest = parts[i + 1:]

        # uvx [--from <pkg>] <command>  OR  uvx <package>
        if basename in ("uvx", "uvx.exe", "uvx.cmd"):
            from_next = False
            for p in rest:
                if p in ("--from", "-f"):
                    from_next = True
                    continue
                if from_next:
                    return p.split("[")[0]
                if not p.startswith("-"):
                    return p.split("[")[0]
            break

        # uv tool run <package>
        # uv run --with <package> <script>
        if basename in ("uv", "uv.exe", "uv.cmd"):
            if not rest:
                break
            subcmd = rest[0].lower()

            if subcmd == "tool" and len(rest) >= 2 and rest[1].lower() in ("run", "install"):
                for p in rest[2:]:
                    if not p.startswith("-"):
                        return p.split("[")[0]

            if subcmd == "run":
                j = 1
                while j < len(rest):
                    p = rest[j]
                    if p == "--with" and j + 1 < len(rest):
                        return rest[j + 1].split(",")[0].strip().split("[")[0]
                    if p.startswith("--with="):
                        return p[7:].split(",")[0].strip().split("[")[0]
                    j += 1
            break

    return None


async def _run_pip_audit(package: str) -> list[dict]:
    """Write a temp requirements.txt and run pip-audit --format json against it."""
    with tempfile.TemporaryDirectory() as tmpdir:
        req_file = Path(tmpdir) / "requirements.txt"
        req_file.write_text(f"{package}\n")

        proc = await asyncio.create_subprocess_exec(
            _PIP_AUDIT,
            "-r", str(req_file),
            "--format", "json",
            "--progress-spinner", "off",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            return []

    if not stdout:
        return []
    try:
        data = json.loads(stdout)
        return data.get("dependencies", [])
    except json.JSONDecodeError:
        return []


def _parse_pip_audit(deps: list[dict], package: str) -> list[Finding]:
    findings: list[Finding] = []

    for dep in deps:
        dep_name = dep.get("name", "?")
        dep_version = dep.get("version", "?")

        for vuln in dep.get("vulns", []):
            vuln_id = vuln.get("id", "?")
            aliases = vuln.get("aliases", [])
            fix_versions = vuln.get("fix_versions", [])
            description = vuln.get("description", "")

            cve_ids = [a for a in aliases if a.upper().startswith("CVE-")]
            cve_str = ", ".join(cve_ids) if cve_ids else "no CVE assigned"

            severity = Severity.HIGH if cve_ids else Severity.MEDIUM
            confidence = 90 if cve_ids else 65

            fix_str = f"fix: {', '.join(fix_versions)}" if fix_versions else "no fix available"
            evidence = f"{dep_name}=={dep_version} — {vuln_id} ({cve_str}) — {fix_str}"

            short_desc = description[:200] + "..." if len(description) > 200 else description

            findings.append(Finding(
                owasp_category=OWASPCategory.MCP04_SUPPLY_CHAIN,
                severity=severity,
                title=f"Supply Chain — '{dep_name}' has vulnerability ({vuln_id})",
                description=(
                    f"Python package '{dep_name}' (dependency of '{package}') has a known "
                    f"vulnerability {vuln_id}. {short_desc}"
                ),
                tool_name=None,
                evidence=evidence,
                remediation=(
                    f"Update '{dep_name}' to {', '.join(fix_versions)}."
                    if fix_versions
                    else f"Update '{dep_name}' to a patched version."
                ),
                confidence=confidence,
            ))

    return findings


class SupplyChainPythonModule(ScanModule):
    owasp_id = "MCP04"
    category = "Supply Chain Attacks"
    name = "supply-chain-python"
    description = (
        "Pre-scan static check: extracts the Python package from a stdio cmd "
        "(uvx / uv run --with), runs pip-audit, and reports known vulnerabilities. "
        "Requires pip-audit. Only applicable to stdio transports."
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

        package = _extract_python_package(session.target)
        if not package:
            return []

        if not shutil.which("pip-audit"):
            return []

        deps = await _run_pip_audit(package)
        return _parse_pip_audit(deps, package)

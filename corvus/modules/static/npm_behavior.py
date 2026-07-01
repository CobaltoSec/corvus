from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Any

import httpx

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

_NPM_REGISTRY = "https://registry.npmjs.org/{pkg}/latest"
_MAX_PACKAGES = 30

_SUSPICIOUS_PATTERNS = re.compile(
    r"curl\b|wget\b|bash\b|sh -c|node -e|powershell\b|exec\(|eval\(|"
    r"require\(['\"]child_process['\"]|spawn\(",
    re.I,
)


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


async def _fetch_npm_scripts(pkg_name: str) -> dict[str, str]:
    """Fetch scripts from npm registry for a package. Returns {} on any error."""
    try:
        url = _NPM_REGISTRY.format(pkg=pkg_name)
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return {}
            data: Any = resp.json()
            scripts = data.get("scripts", {})
            return {k: v for k, v in scripts.items() if isinstance(k, str) and isinstance(v, str)}
    except Exception:
        return {}


def _check_scripts(pkg_name: str, scripts: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []

    for script_name, script_value in scripts.items():
        is_install_hook = script_name in ("preinstall", "install", "postinstall")
        if not is_install_hook:
            continue

        is_suspicious = bool(_SUSPICIOUS_PATTERNS.search(script_value))

        if is_suspicious:
            findings.append(Finding(
                owasp_category=OWASPCategory.MCP04_SUPPLY_CHAIN,
                severity=Severity.HIGH,
                title=f"Suspicious shell command in '{pkg_name}' npm {script_name} script",
                description=(
                    f"Package '{pkg_name}' has a '{script_name}' script containing suspicious "
                    "commands (curl/wget/bash/eval/exec/child_process). "
                    "This can execute arbitrary code when the package is installed."
                ),
                tool_name=None,
                evidence=f"{script_name}: {script_value[:300]}",
                confidence=80,
                remediation=(
                    f"Audit '{pkg_name}' for supply chain compromise. "
                    "Avoid packages that download or execute code at install time."
                ),
            ))
        elif script_name == "postinstall":
            findings.append(Finding(
                owasp_category=OWASPCategory.MCP04_SUPPLY_CHAIN,
                severity=Severity.MEDIUM,
                title=f"Package '{pkg_name}' has postinstall script — potential code execution on install",
                description=(
                    f"Package '{pkg_name}' defines a postinstall script: '{script_value[:200]}'. "
                    "Postinstall scripts run automatically during npm install and can be misused "
                    "for supply chain attacks."
                ),
                tool_name=None,
                evidence=f"postinstall: {script_value[:300]}",
                confidence=65,
                remediation=(
                    f"Review the postinstall script of '{pkg_name}'. "
                    "Use --ignore-scripts flag during installation if this package does not require scripts."
                ),
            ))

    return findings


class NpmBehaviorModule(ScanModule):
    owasp_id = "MCP04"
    category = "Supply Chain Attacks"
    name = "npm-behavior"
    description = (
        "Static check: queries npm registry for suspicious install scripts (postinstall/preinstall) "
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
                scripts = await _fetch_npm_scripts(pkg_name)
            except Exception:
                continue
            findings.extend(_check_scripts(pkg_name, scripts))
        return findings

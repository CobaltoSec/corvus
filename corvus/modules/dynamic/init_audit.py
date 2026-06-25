from __future__ import annotations

import re
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

_DOWNGRADE_VERSIONS = ["1.0", "2024-01-01", "", "0.1"]


class InitAuditModule(ScanModule):
    owasp_id = "MCP07"
    category = "Insufficient Auth & Authorization"
    name = "init-audit"
    description = (
        "Audits the initialize handshake: checks serverInfo for injection chars, "
        "probes protocol version downgrade acceptance"
    )
    is_static = False

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Static checks on serverInfo from the already-captured surface
        for field, value in [("server_name", surface.server_name), ("server_version", surface.server_version)]:
            if value and _CONTROL_CHARS.search(value):
                findings.append(Finding(
                    owasp_category=OWASPCategory.MCP07_AUTH_AUDIT,
                    severity=Severity.HIGH,
                    title=f"serverInfo injection — control characters in '{field}'",
                    description=(
                        f"The server's {field} field contains control characters "
                        "(e.g. \\n, \\r, \\x00). This can break log parsers, inject "
                        "newlines into audit trails, or cause parser confusion."
                    ),
                    evidence=repr(value),
                    confidence=90,
                    remediation="Strip all control characters from serverInfo name and version fields.",
                ))

        # Dynamic: protocol version downgrade probe
        downgrade_accepted: list[str] = []
        for version in _DOWNGRADE_VERSIONS:
            accepted = await _probe_initialize(transport, version)
            if accepted:
                downgrade_accepted.append(version or '""')

        if downgrade_accepted:
            findings.append(Finding(
                owasp_category=OWASPCategory.MCP07_AUTH_AUDIT,
                severity=Severity.MEDIUM,
                title="initialize accepts protocol version downgrade",
                description=(
                    f"The server accepted initialize requests with downgraded protocol versions: "
                    f"{downgrade_accepted}. Servers should reject versions older than the minimum "
                    "supported to prevent feature-downgrade attacks."
                ),
                evidence=f"Accepted versions: {downgrade_accepted}",
                confidence=75,
                remediation=(
                    "Validate the requested protocolVersion against a minimum supported version. "
                    "Return a JSON-RPC error if the client requests an unsupported version."
                ),
            ))

        return findings


async def _probe_initialize(transport: MCPTransport, version: str) -> bool:
    """Return True if the server responds without error to an initialize with the given version."""
    try:
        result: Any = await transport.send_request("initialize", {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {"name": "corvus-probe", "version": "0.0.1"},
        })
        # A compliant server should return an error for unsupported versions;
        # a non-error response (with a result dict containing serverInfo) means it accepted.
        return isinstance(result, dict) and "serverInfo" in result
    except Exception:
        return False

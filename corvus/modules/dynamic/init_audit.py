from __future__ import annotations

import re
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# Probe versions: past, empty, and far-future to detect servers that accept any value.
_PROBE_VERSIONS = ["9999-99-99", "2030-01-01", "1.0", "2024-01-01", "", "0.1"]


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

        # Dynamic: protocol version probe — past, empty, and far-future values
        versions_accepted: list[str] = []
        for version in _PROBE_VERSIONS:
            accepted = await _probe_initialize(transport, version)
            if accepted:
                versions_accepted.append(version or '""')

        if versions_accepted:
            has_future = any(v.startswith("9999") or v.startswith("2030") for v in versions_accepted)
            severity = Severity.MEDIUM
            title = "initialize accepts protocol version downgrade"
            desc_extra = (
                " The server also accepted far-future versions, indicating no version validation at all."
                if has_future else ""
            )
            findings.append(Finding(
                owasp_category=OWASPCategory.MCP07_AUTH_AUDIT,
                severity=severity,
                title=title,
                description=(
                    f"The server accepted initialize with arbitrary protocol versions: "
                    f"{versions_accepted}.{desc_extra} "
                    "Servers should reject versions outside their supported range "
                    "to prevent feature-downgrade attacks."
                ),
                evidence=f"Accepted versions: {versions_accepted}",
                confidence=75,
                remediation=(
                    "Validate protocolVersion against a supported range. "
                    "Return a JSON-RPC error for versions outside that range."
                ),
            ))

        # Missing protocolVersion field — server should return error, not crash
        missing_field = await _probe_missing_field(transport)
        if missing_field == "crash":
            findings.append(Finding(
                owasp_category=OWASPCategory.MCP07_AUTH_AUDIT,
                severity=Severity.MEDIUM,
                title="initialize crash — missing protocolVersion causes unhandled error",
                description=(
                    "Sending initialize without the required protocolVersion field "
                    "caused the server to crash or return an unexpected result. "
                    "Servers must validate required fields and return -32602 (Invalid params)."
                ),
                evidence="initialize({capabilities:{}, clientInfo:{...}}) — no protocolVersion",
                confidence=70,
                remediation="Add required-field validation to the initialize handler.",
            ))

        # Type confusion: protocolVersion as integer instead of string
        type_confused = await _probe_type_confusion(transport)
        if type_confused:
            findings.append(Finding(
                owasp_category=OWASPCategory.MCP07_AUTH_AUDIT,
                severity=Severity.LOW,
                title="initialize accepts type-confused protocolVersion (integer instead of string)",
                description=(
                    "The server accepted an initialize request where protocolVersion was an "
                    "integer (42) instead of a string. Strict type checking prevents "
                    "parser confusion and unexpected coercion behavior."
                ),
                evidence="protocolVersion: 42 (integer) → server returned serverInfo",
                confidence=65,
                remediation="Validate that protocolVersion is a string before processing.",
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
        return isinstance(result, dict) and "serverInfo" in result
    except Exception:
        return False


async def _probe_missing_field(transport: MCPTransport) -> str:
    """Send initialize without protocolVersion. Returns 'crash', 'error', or 'ok'."""
    try:
        result: Any = await transport.send_request("initialize", {
            "capabilities": {},
            "clientInfo": {"name": "corvus-probe", "version": "0.0.1"},
        })
        # If server returned a valid serverInfo without the required field, report as crash
        if isinstance(result, dict) and "serverInfo" in result:
            return "crash"
        return "ok"
    except Exception:
        return "error"  # Expected: server should return JSON-RPC error — not a finding


async def _probe_type_confusion(transport: MCPTransport) -> bool:
    """Send initialize with protocolVersion as integer. Return True if server accepts it."""
    try:
        result: Any = await transport.send_request("initialize", {
            "protocolVersion": 42,  # integer instead of string
            "capabilities": {},
            "clientInfo": {"name": "corvus-probe", "version": "0.0.1"},
        })
        return isinstance(result, dict) and "serverInfo" in result
    except Exception:
        return False



"""logging_probe.py — MCP logging/setLevel abuse probe (EXT11)."""
from __future__ import annotations

import asyncio
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

_LOGGING_TIMEOUT = 5.0


async def _set_level(transport: MCPTransport, level: str, req_id: int) -> Any:
    """Call logging/setLevel; return result dict, or raise on error/timeout."""
    return await asyncio.wait_for(
        transport.send_request("logging/setLevel", {"level": level}),
        timeout=_LOGGING_TIMEOUT,
    )


class LoggingProbeModule(ScanModule):
    owasp_id = "EXT11"
    category = "Log Level Abuse"
    name = "logging-probe"
    description = (
        "Tests whether the MCP server allows unauthenticated external escalation "
        "of server log verbosity via logging/setLevel."
    )
    is_static = False

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Probe 1 — attempt to set log level to debug
        try:
            result = await _set_level(transport, "debug", 8100)
        except asyncio.TimeoutError:
            return findings
        except Exception:
            # MethodNotFound or auth error → normal behavior or not supported
            return findings

        if result is None:
            return findings

        # Success: server allowed level escalation
        escalation_finding = Finding(
            owasp_category=OWASPCategory.EXT11_LOG_LEVEL_ABUSE,
            severity=Severity.HIGH,
            title="Server allows external log level escalation to DEBUG",
            description=(
                "The MCP server accepted an unauthenticated logging/setLevel request "
                "with level='debug'. This may expose tokens, internal paths, and "
                "sensitive state in log streams accessible to the operator."
            ),
            evidence="logging/setLevel with level='debug' returned success",
            confidence=85,
            remediation="Restrict logging/setLevel to admin contexts or disable it entirely.",
        )
        findings.append(escalation_finding)

        # Probe 2 — test invalid level
        try:
            inv_result = await _set_level(transport, "INVALID_LEVEL_CORVUS", 8101)
            if inv_result is not None:
                findings.append(Finding(
                    owasp_category=OWASPCategory.EXT11_LOG_LEVEL_ABUSE,
                    severity=Severity.MEDIUM,
                    title="Server accepts arbitrary logging levels without validation",
                    description=(
                        "logging/setLevel accepted the value 'INVALID_LEVEL_CORVUS', "
                        "indicating the server does not validate log level values."
                    ),
                    evidence="logging/setLevel with level='INVALID_LEVEL_CORVUS' returned success",
                    confidence=75,
                    remediation="Validate logging level against the MCP-defined set (debug/info/warning/error/critical).",
                ))
        except Exception:
            pass  # Rejection of invalid level is correct behavior

        # Probe 3 — emergency level (update evidence on escalation finding)
        try:
            emerg_result = await _set_level(transport, "emergency", 8102)
            if emerg_result is not None:
                # Augment the escalation finding evidence
                escalation_finding.evidence = (
                    "logging/setLevel with level='debug' and level='emergency' both returned success"
                )
        except Exception:
            pass

        return findings

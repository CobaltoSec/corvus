"""Sample plugin for Corvus plugin-discovery tests.

This file is intentionally placed in tests/fixtures/ so that
discover_plugins(plugin_dirs=["tests/fixtures"]) can find it.
"""
from __future__ import annotations

from corvus.core.models import Finding, MCPSurface, OWASPCategory, Severity
from corvus.core.session import ScanSession
from corvus.modules.base import ScanModule
from corvus.transport.base import MCPTransport


class SampleCustomModule(ScanModule):
    owasp_id = "MCP01"
    category = "Custom Check"
    name = "custom-sample"
    description = "Sample plugin module used by Corvus plugin-discovery tests"
    is_static = True

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        return [
            Finding(
                owasp_category=OWASPCategory.MCP03_TOOL_POISONING,
                severity=Severity.INFO,
                title="Custom plugin executed successfully",
                description="Finding emitted by the sample plugin to confirm it was loaded.",
                remediation="No action required — test plugin only.",
            )
        ]

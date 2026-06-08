from __future__ import annotations

from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...payloads.engine import PayloadEngine
from ...transport.base import MCPTransport


class SchemaBypassModule(ScanModule):
    owasp_id = "MCP05"
    category = "Schema Bypass"
    name = "schema-bypass"
    description = "Tests whether tools properly reject inputs that violate their declared schema"
    is_static = False

    def __init__(self):
        self.engine = PayloadEngine()

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for tool in surface.tools:
            schema = tool.input_schema
            properties: dict[str, Any] = schema.get("properties", {})
            required: list[str] = schema.get("required", [])

            # Test 1: call with completely empty args when fields are required
            if required:
                if await self._accepted(transport, tool.name, {}):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.MCP05_SCHEMA_BYPASS,
                        severity=Severity.MEDIUM,
                        title=f"'{tool.name}' accepts missing required fields",
                        description=f"Tool succeeded with empty arguments despite required: {required}",
                        tool_name=tool.name,
                        remediation="Validate that all required parameters are present before processing.",
                    ))

            # Test 2: wrong type on first required param
            for param in required[:1]:
                param_schema = properties.get(param, {})
                ptype = param_schema.get("type", "string")
                for payload in self.engine.schema_bypass_payloads(ptype):
                    args = self.engine.build_args(properties, required, param, payload)
                    if await self._accepted(transport, tool.name, args):
                        findings.append(Finding(
                            owasp_category=OWASPCategory.MCP05_SCHEMA_BYPASS,
                            severity=Severity.LOW,
                            title=f"'{tool.name}.{param}' silently accepts wrong type",
                            description=(
                                f"Expected type '{ptype}', sent {type(payload).__name__} "
                                f"value '{payload}' — no error returned."
                            ),
                            tool_name=tool.name,
                            parameter=param,
                            payload=str(payload),
                            remediation="Validate parameter types strictly and return clear JSON-RPC errors on mismatch.",
                        ))
                        break  # one finding per param

            # Test 3: prototype pollution via extra fields
            if properties:
                first_required = required[0] if required else next(iter(properties))
                ptype = properties.get(first_required, {}).get("type", "string")
                args = self.engine.build_args(properties, required, first_required,
                                              self.engine.benign_default(ptype))
                args["__proto__"] = {"polluted": True}
                if await self._accepted(transport, tool.name, args):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.MCP05_SCHEMA_BYPASS,
                        severity=Severity.LOW,
                        title=f"'{tool.name}' accepts undeclared extra fields",
                        description="Tool accepted arguments containing '__proto__' without error.",
                        tool_name=tool.name,
                        remediation="Reject calls containing parameters not declared in inputSchema.",
                    ))

        return findings

    async def _accepted(self, transport: MCPTransport, tool_name: str, args: dict) -> bool:
        """Return True if the tool call succeeded without an error response."""
        try:
            await transport.send_request("tools/call", {"name": tool_name, "arguments": args})
            return True
        except Exception:
            return False

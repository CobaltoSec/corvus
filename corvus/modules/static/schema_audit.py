from __future__ import annotations

import re

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport


# Tools whose purpose is inherently optional-param (search, query, list, view…)
_SEARCH_TOOL_NAME = re.compile(r"search|query|list|get|doc|view|display|read", re.I)


class SchemaAuditModule(ScanModule):
    owasp_id = "EXT02"
    category = "Schema Audit"
    name = "schema-audit"
    description = "Audits tool schemas for weak definitions that expand the attack surface"
    is_static = True

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for tool in surface.tools:
            schema = tool.input_schema
            properties: dict = schema.get("properties", {})

            # Tool has no description
            if not tool.description.strip():
                findings.append(Finding(
                    owasp_category=OWASPCategory.EXT02_SCHEMA_AUDIT,
                    severity=Severity.LOW,
                    title=f"'{tool.name}' has no description",
                    description="Tools without descriptions cannot be audited for hidden intent.",
                    tool_name=tool.name,
                    remediation="Add a clear, concise description to every tool.",
                    confidence=80,
                ))

            # additionalProperties: true — accepts arbitrary keys
            if schema.get("additionalProperties") is True:
                findings.append(Finding(
                    owasp_category=OWASPCategory.EXT02_SCHEMA_AUDIT,
                    severity=Severity.MEDIUM,
                    title=f"'{tool.name}' accepts arbitrary additional properties",
                    description="additionalProperties: true allows unexpected parameters that may bypass validation logic.",
                    tool_name=tool.name,
                    remediation="Set additionalProperties: false and enumerate all expected parameters explicitly.",
                    confidence=80,
                ))

            # Parameters without type constraints
            for param, param_schema in properties.items():
                if "type" not in param_schema and "$ref" not in param_schema:
                    findings.append(Finding(
                        owasp_category=OWASPCategory.EXT02_SCHEMA_AUDIT,
                        severity=Severity.LOW,
                        title=f"Parameter '{param}' in '{tool.name}' has no type constraint",
                        description="Untyped parameters accept any value, making input validation harder to enforce.",
                        tool_name=tool.name,
                        parameter=param,
                        remediation=f"Add an explicit type to parameter '{param}'.",
                        confidence=80,
                    ))

            # Tool has properties but no required field
            if properties and "required" not in schema and not _SEARCH_TOOL_NAME.search(tool.name):
                findings.append(Finding(
                    owasp_category=OWASPCategory.EXT02_SCHEMA_AUDIT,
                    severity=Severity.INFO,
                    title=f"'{tool.name}' defines no required fields",
                    description="All parameters are implicitly optional. Verify this is intentional.",
                    tool_name=tool.name,
                    remediation="Declare required parameters explicitly to enforce correct usage.",
                    confidence=70,
                ))

        return findings

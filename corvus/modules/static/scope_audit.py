from __future__ import annotations

import re

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

# Tool name contains privilege keyword anywhere
_HIGH_NAME_SCOPE = re.compile(
    r"\b(admin|root|superuser|elevated|privileged)\b", re.I
)

# Description explicitly claims unrestricted or broad scope
_HIGH_DESC_SCOPE: list[re.Pattern[str]] = [
    re.compile(r"unrestricted\s+access", re.I),
    re.compile(r"without\s+restriction", re.I),
    re.compile(r"no\s+restriction", re.I),
    re.compile(r"full\s+access", re.I),
    re.compile(r"any\s+(path|file|user|directory|resource)", re.I),
    re.compile(r"all\s+(files|users|data|resources)", re.I),
]

# Read-only name prefix
_READ_PREFIX = re.compile(r"^(read|get|fetch|list)_", re.I)

# Write verbs in description that contradict a read-only name
_WRITE_VERBS = re.compile(
    r"\b(write|create|delete|modify|update|overwrite|append|remove|clear)\b", re.I
)

# Softer scope escalation signals in description
_MEDIUM_DESC_SCOPE: list[re.Pattern[str]] = [
    re.compile(r"\boverride\b", re.I),
    re.compile(r"\bescalat(e|ed|ing|ion)\b", re.I),
    re.compile(r"\ball[_\-]access\b", re.I),
    re.compile(r"\bunlimited\b", re.I),
]


class ScopeAuditModule(ScanModule):
    owasp_id = "MCP02"
    category = "Privilege Escalation via Scope Creep"
    name = "scope-audit"
    description = (
        "Static analysis that flags tool names and descriptions suggesting "
        "privilege escalation or scope broader than what the tool claims to do"
    )
    is_static = True

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for tool in surface.tools:
            result = self._check(tool.name, tool.description)
            if result:
                findings.append(result)
        return findings

    def _check(self, name: str, description: str) -> Finding | None:
        # HIGH: name contains privileged keyword
        m = _HIGH_NAME_SCOPE.search(name)
        if m:
            return Finding(
                owasp_category=OWASPCategory.MCP02_SCOPE_CREEP,
                severity=Severity.HIGH,
                title=f"Scope Creep — '{name}' exposes elevated-privilege access",
                description=(
                    f"Tool name '{name}' contains a privilege keyword ('{m.group()}') "
                    "indicating elevated scope. Privileged tools should not be reachable "
                    "without explicit scope restrictions and authorization checks."
                ),
                tool_name=name,
                evidence=description[:300] or None,
                remediation=(
                    "Restrict privileged tools to authorized callers. Document the exact "
                    "scope of access and enforce it server-side. Consider removing them "
                    "from the public MCP tool surface entirely."
                ),
                confidence=85,
            )

        # HIGH: description claims unrestricted or broad scope
        for pattern in _HIGH_DESC_SCOPE:
            m = pattern.search(description)
            if m:
                return Finding(
                    owasp_category=OWASPCategory.MCP02_SCOPE_CREEP,
                    severity=Severity.HIGH,
                    title=f"Scope Creep — '{name}' claims unrestricted access scope",
                    description=(
                        f"Tool '{name}' description contains a broad-scope claim: '{m.group()}'. "
                        "Unrestricted scope tools risk being exploited for lateral movement "
                        "or privilege escalation in an MCP session."
                    ),
                    tool_name=name,
                    evidence=description[:300],
                    remediation=(
                        "Scope tools to the minimum necessary access. Replace 'any path' / "
                        "'all files' with explicit allowlists. Validate and restrict inputs "
                        "server-side."
                    ),
                    confidence=85,
                )

        # MEDIUM: read-only name but write capable description
        if _READ_PREFIX.match(name) and _WRITE_VERBS.search(description):
            m_write = _WRITE_VERBS.search(description)
            return Finding(
                owasp_category=OWASPCategory.MCP02_SCOPE_CREEP,
                severity=Severity.MEDIUM,
                title=f"Scope Creep — '{name}' is named read-only but description implies write access",
                description=(
                    f"Tool '{name}' has a read-only prefix but its description mentions "
                    f"write operations ('{m_write.group() if m_write else ''}'), creating "
                    "a scope mismatch that callers and LLMs may be unable to detect."
                ),
                tool_name=name,
                evidence=description[:300],
                remediation=(
                    "Separate read and write operations into distinct tools. Ensure tool "
                    "names accurately reflect their full capabilities."
                ),
                confidence=70,
            )

        # MEDIUM: scope escalation keywords in description
        for pattern in _MEDIUM_DESC_SCOPE:
            m = pattern.search(description)
            if m:
                return Finding(
                    owasp_category=OWASPCategory.MCP02_SCOPE_CREEP,
                    severity=Severity.MEDIUM,
                    title=f"Scope Creep — '{name}' description suggests privilege escalation",
                    description=(
                        f"Tool '{name}' description contains a scope-escalation signal: "
                        f"'{m.group()}'. This may indicate the tool operates beyond its "
                        "declared purpose."
                    ),
                    tool_name=name,
                    evidence=description[:300],
                    remediation=(
                        "Review and restrict the tool's effective scope. Remove or replace "
                        "terms that imply privilege escalation."
                    ),
                    confidence=70,
                )

        return None

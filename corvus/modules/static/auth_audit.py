from __future__ import annotations

import re

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

# Description patterns that indicate an active auth bypass (CRITICAL)
_CRITICAL_DESC: list[re.Pattern[str]] = [
    re.compile(r"bypass(es|ing)?\s+auth(entication)?", re.I),
    re.compile(r"skip(s|ping)?\s+(auth|verification|validation)", re.I),
]

# Description patterns that state auth is absent — descriptive, not an active bypass (HIGH)
_HIGH_AUTH_ABSENT: list[re.Pattern[str]] = [
    re.compile(r"no\s+auth(entication)?\s+required", re.I),
    re.compile(r"without\s+auth(entication)?", re.I),
]

# Description patterns suggesting access-restricted use without auth enforcement
_HIGH_DESC: list[re.Pattern[str]] = [
    re.compile(r"\b(admin|root|superuser|privileged|operator)\s+only\b", re.I),
    re.compile(r"for\s+(admin|internal|privileged|system)\s+use\s+only", re.I),
    re.compile(r"\binternal\s+use\s+only\b", re.I),
    re.compile(r"\bdebug\s+(mode|endpoint|access)\b", re.I),
    re.compile(r"\bdo\s+not\s+(expose|publish|share)\b", re.I),
]

# Tool name prefixes/suffixes that suggest restricted internal or admin access
_HIGH_NAME: list[re.Pattern[str]] = [
    re.compile(r"^(admin|internal|debug|privileged|root|sys|hidden)_", re.I),
    re.compile(r"_(admin|internal|debug|privileged|root|hidden)$", re.I),
]

# Softer signals — auth mentioned as conditional or advisory
_MEDIUM_DESC: list[re.Pattern[str]] = [
    re.compile(r"if\s+(authenticated|logged\s+in|authorized)", re.I),
    re.compile(r"optional\s+auth(entication)?", re.I),
    re.compile(r"auth(entication)?\s+(may|can)\s+be\s+(skipped|omitted|bypassed)", re.I),
]


class AuthAuditModule(ScanModule):
    owasp_id = "MCP07"
    category = "Insufficient Auth & Authorization"
    name = "auth-audit"
    description = (
        "Static analysis that flags tool names and descriptions suggesting missing, "
        "optional, or bypassable authentication and access controls"
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
            for finding in self._check(tool.name, tool.description):
                if finding.severity == Severity.CRITICAL:
                    verified = await self._verify_critical(transport, tool.name)
                    if not verified:
                        finding = finding.model_copy(update={"severity": Severity.HIGH})
                findings.append(finding)
        return findings

    async def _verify_critical(self, transport: MCPTransport, tool_name: str) -> bool:
        """Mitigate static FP: confirm auth bypass by probing the tool and checking for a success response."""
        try:
            result = await transport.send_request(
                "tools/call", {"name": tool_name, "arguments": {}}
            )
            if not isinstance(result, dict):
                return False
            if result.get("isError"):
                return False
            content = result.get("content", [])
            return bool(content)
        except Exception:
            return False

    def _check(self, name: str, description: str) -> list[Finding]:
        found: list[Finding] = []

        # CRITICAL: description explicitly says no auth required
        for pattern in _CRITICAL_DESC:
            m = pattern.search(description)
            if m:
                found.append(Finding(
                    owasp_category=OWASPCategory.MCP07_AUTH_AUDIT,
                    severity=Severity.CRITICAL,
                    title=f"Auth Bypass — '{name}' explicitly claims no authentication needed",
                    description=(
                        f"Description of '{name}' contains a phrase indicating authentication "
                        f"is absent or bypassable: '{m.group()}'."
                    ),
                    tool_name=name,
                    evidence=description[:300],
                    remediation=(
                        "Remove documentation of auth bypasses. All privileged tools must enforce "
                        "authentication and authorization at the server layer, not rely on callers."
                    ),
                    confidence=85,
                ))
                return found  # one critical per tool is enough

        # HIGH: description states auth is absent (descriptive — may be accurate for public tools)
        for pattern in _HIGH_AUTH_ABSENT:
            m = pattern.search(description)
            if m:
                found.append(Finding(
                    owasp_category=OWASPCategory.MCP07_AUTH_AUDIT,
                    severity=Severity.HIGH,
                    title=f"Auth Absent — '{name}' explicitly states no authentication needed",
                    description=(
                        f"Description of '{name}' states authentication is not required: "
                        f"'{m.group()}'. If this tool accesses sensitive data or actions, "
                        "missing auth is a security risk."
                    ),
                    tool_name=name,
                    evidence=description[:300],
                    remediation=(
                        "If this tool exposes sensitive operations, enforce authentication. "
                        "If it is intentionally public, document the trust boundary explicitly."
                    ),
                    confidence=70,
                ))
                return found

        # HIGH: description implies privileged/restricted access
        for pattern in _HIGH_DESC:
            m = pattern.search(description)
            if m:
                found.append(Finding(
                    owasp_category=OWASPCategory.MCP07_AUTH_AUDIT,
                    severity=Severity.HIGH,
                    title=f"Auth Bypass — '{name}' is marked as restricted but has no auth signal",
                    description=(
                        f"Tool '{name}' description suggests restricted access "
                        f"('{m.group()}') without documenting how that restriction is enforced."
                    ),
                    tool_name=name,
                    evidence=description[:300],
                    remediation=(
                        "Explicitly document the authentication mechanism for restricted tools, "
                        "or remove them from the public tool surface entirely."
                    ),
                    confidence=85,
                ))
                return found

        # HIGH: name pattern signals internal/admin/debug access
        for pattern in _HIGH_NAME:
            if pattern.search(name):
                found.append(Finding(
                    owasp_category=OWASPCategory.MCP07_AUTH_AUDIT,
                    severity=Severity.HIGH,
                    title=f"Auth Bypass — '{name}' uses a restricted-access naming convention",
                    description=(
                        f"Tool name '{name}' follows a naming pattern (admin_, internal_, debug_, etc.) "
                        "that implies restricted access, but no authentication enforcement is visible."
                    ),
                    tool_name=name,
                    remediation=(
                        "Restrict access-controlled tools using server-side auth checks. "
                        "Do not rely on naming conventions as a security boundary."
                    ),
                    confidence=75,
                ))
                return found

        # MEDIUM: auth is mentioned as optional or conditional
        for pattern in _MEDIUM_DESC:
            m = pattern.search(description)
            if m:
                found.append(Finding(
                    owasp_category=OWASPCategory.MCP07_AUTH_AUDIT,
                    severity=Severity.MEDIUM,
                    title=f"Auth Bypass — '{name}' treats authentication as optional",
                    description=(
                        f"Tool '{name}' description implies authentication may be skipped: "
                        f"'{m.group()}'."
                    ),
                    tool_name=name,
                    evidence=description[:300],
                    remediation="Enforce authentication unconditionally. Remove conditional auth paths.",
                    confidence=70,
                ))
                return found

        return found

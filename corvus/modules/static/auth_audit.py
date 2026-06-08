from __future__ import annotations

import re

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

# Description patterns that indicate privileged access with explicitly absent auth
_CRITICAL_DESC: list[re.Pattern[str]] = [
    re.compile(r"no\s+auth(entication)?\s+required", re.I),
    re.compile(r"bypass(es|ing)?\s+auth(entication)?", re.I),
    re.compile(r"skip(s|ping)?\s+(auth|verification|validation)", re.I),
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
    owasp_id = "MCP08"
    category = "Auth Bypass"
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
            findings.extend(self._check(tool.name, tool.description))
        return findings

    def _check(self, name: str, description: str) -> list[Finding]:
        found: list[Finding] = []

        # CRITICAL: description explicitly says no auth required
        for pattern in _CRITICAL_DESC:
            m = pattern.search(description)
            if m:
                found.append(Finding(
                    owasp_category=OWASPCategory.MCP08_AUTH_BYPASS,
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
                ))
                return found  # one critical per tool is enough

        # HIGH: description implies privileged/restricted access
        for pattern in _HIGH_DESC:
            m = pattern.search(description)
            if m:
                found.append(Finding(
                    owasp_category=OWASPCategory.MCP08_AUTH_BYPASS,
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
                ))
                return found

        # HIGH: name pattern signals internal/admin/debug access
        for pattern in _HIGH_NAME:
            if pattern.search(name):
                found.append(Finding(
                    owasp_category=OWASPCategory.MCP08_AUTH_BYPASS,
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
                ))
                return found

        # MEDIUM: auth is mentioned as optional or conditional
        for pattern in _MEDIUM_DESC:
            m = pattern.search(description)
            if m:
                found.append(Finding(
                    owasp_category=OWASPCategory.MCP08_AUTH_BYPASS,
                    severity=Severity.MEDIUM,
                    title=f"Auth Bypass — '{name}' treats authentication as optional",
                    description=(
                        f"Tool '{name}' description implies authentication may be skipped: "
                        f"'{m.group()}'."
                    ),
                    tool_name=name,
                    evidence=description[:300],
                    remediation="Enforce authentication unconditionally. Remove conditional auth paths.",
                ))
                return found

        return found

from __future__ import annotations

import re

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

# Imperative phrases that signal the LLM is being directed to call another tool
_IMPERATIVE_RE = re.compile(
    r"\b(always|must|required?\s+to|you\s+should|you\s+must|"
    r"before\s+(using|calling|invoking|running)|after\s+(using|calling|invoking|running)|"
    r"first\s+call|failure\s+to\s+invoke|requires?\s+you\s+to|"
    r"before\s+calling|after\s+calling|depends?\s+on|"
    r"you\s+are\s+required|do\s+not\s+use\s+without)\b",
    re.I,
)

# Compliance language used to manufacture urgency
_COMPLIANCE_RE = re.compile(
    r"\b(compliance|policy|required\s+by|mandated|violat(e|ion)|audit\s+trail|"
    r"security\s+policy|must\s+be\s+called|non[_\-]?compliant)\b",
    re.I,
)


class ToolChainingModule(ScanModule):
    owasp_id = "EXT06"
    category = "Cross-tool Instruction Chaining"
    name = "tool-chaining"
    description = (
        "Detects tool descriptions that reference other tools on the same server "
        "with imperative or compliance language, signaling dependency injection or "
        "forced call-chain manipulation"
    )
    is_static = True

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        if len(surface.tools) < 2:
            return []

        tool_names = [t.name for t in surface.tools]
        findings: list[Finding] = []

        for tool in surface.tools:
            if not tool.description:
                continue

            desc = tool.description
            has_imperative = bool(_IMPERATIVE_RE.search(desc))
            has_compliance = bool(_COMPLIANCE_RE.search(desc))

            if not (has_imperative or has_compliance):
                continue

            # Check if description references any other tool on this server
            referenced = [
                other for other in tool_names
                if other != tool.name and _tool_referenced(other, desc)
            ]
            if not referenced:
                continue

            severity = Severity.HIGH if has_compliance else Severity.MEDIUM
            confidence = 80 if has_compliance else 65

            findings.append(Finding(
                owasp_category=OWASPCategory.EXT06_TOOL_CHAINING,
                severity=severity,
                title=f"Tool Chaining — '{tool.name}' directs LLM to call {referenced[0]}",
                description=(
                    f"Tool '{tool.name}' description references tool(s) "
                    f"{', '.join(repr(r) for r in referenced)} "
                    f"from the same server using "
                    + ("compliance/policy language" if has_compliance else "imperative language")
                    + ". This pattern can force an LLM into an unintended call chain or "
                    "manufacture urgency to invoke a privileged tool."
                ),
                tool_name=tool.name,
                evidence=desc[:300],
                remediation=(
                    "Tool descriptions should describe what the tool does — not instruct "
                    "the LLM on what other tools to call. Remove cross-tool directives "
                    "and let the caller decide the execution order."
                ),
                confidence=confidence,
            ))

        return findings


def _tool_referenced(tool_name: str, text: str) -> bool:
    """Return True if tool_name appears as a word or quoted identifier in text."""
    # Escape for regex — tool names can contain hyphens and underscores
    escaped = re.escape(tool_name)
    # Match as whole identifier (word boundary or surrounded by quotes/backticks)
    pattern = re.compile(
        rf"(?:^|[\s\(\[\{{'\"`,])({escaped})(?:[\s\)\]\}}'\"`,]|$)",
        re.I,
    )
    return bool(pattern.search(text))

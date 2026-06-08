from __future__ import annotations

import re

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

# Tool name patterns for audit-log tampering (anti-forensics)
_CRITICAL_NAME: list[re.Pattern[str]] = [
    re.compile(r"^(clear|delete|purge|wipe|disable|drop)_.*log", re.I),
    re.compile(r"^(truncate|flush|erase)_.*audit", re.I),
    re.compile(r"log.*(clear|wipe|delete|purge|disable)$", re.I),
]

# Description patterns for audit-log tampering
_CRITICAL_DESC: list[re.Pattern[str]] = [
    re.compile(r"clears?\s+(the\s+)?(audit|access|event|system).*\blog\b", re.I),
    re.compile(r"delet(e|ing|es)\s+(the\s+)?(audit|access|event|system).*\blog\b", re.I),
    re.compile(r"purge[sd]?\s+(the\s+)?(audit|access|event|system).*\blog\b", re.I),
    re.compile(r"disabl(e|es|ing)\s+(audit|logging|log\s+rotation)", re.I),
    re.compile(r"wipe[sd]?\s+(the\s+)?(audit|access|event).*\blog\b", re.I),
]

# Tool name pattern for raw log data exposure (logs often contain credentials and PII)
_HIGH_NAME: re.Pattern[str] = re.compile(
    r"^(get|read|fetch|download|export|dump|retrieve|view|access)_"
    r"(audit|access|event|system|security|application|server)_?log",
    re.I,
)

# Description patterns for log data exposure
_HIGH_DESC: list[re.Pattern[str]] = [
    re.compile(r"returns?\s+(raw\s+)?log\s+(data|entries|records)", re.I),
    re.compile(r"retrieves?\s+(the\s+)?(audit|access|event|server)\s+log", re.I),
    re.compile(r"exposes?\s+(the\s+)?(audit|server|application)\s+log", re.I),
    re.compile(r"(audit|access|event)\s+log\s+(content|data|records|entries)", re.I),
]

# Description patterns for explicitly-absent logging (unaudited operations)
_MEDIUM_DESC: list[re.Pattern[str]] = [
    re.compile(r"logging\s+(is\s+)?(disabled|turned\s+off|suppressed)", re.I),
    re.compile(r"no\s+(audit|access|event)\s+log(ging)?", re.I),
    re.compile(r"(skip|bypass|omit)\s+(audit|logging)", re.I),
]


class LogAuditModule(ScanModule):
    owasp_id = "MCP10"
    category = "Logging & Monitoring Failures"
    name = "log-audit"
    description = (
        "Static analysis that detects tools exposing or tampering with audit logs, "
        "enabling anti-forensic techniques or leaking sensitive operational data"
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
        # CRITICAL: tool can destroy the audit trail (attacker anti-forensics)
        for pattern in _CRITICAL_NAME:
            if pattern.search(name):
                return [Finding(
                    owasp_category=OWASPCategory.MCP10_LOG_AUDIT,
                    severity=Severity.CRITICAL,
                    title=f"Log Audit Failure — '{name}' can destroy the audit trail",
                    description=(
                        f"Tool name '{name}' indicates it can clear, delete, or disable audit logs. "
                        "An attacker can invoke this tool to erase evidence of malicious activity."
                    ),
                    tool_name=name,
                    remediation=(
                        "Remove log-manipulation tools from the MCP surface. If required, "
                        "restrict them behind strong authentication and a write-once audit store."
                    ),
                )]

        for pattern in _CRITICAL_DESC:
            m = pattern.search(description)
            if m:
                return [Finding(
                    owasp_category=OWASPCategory.MCP10_LOG_AUDIT,
                    severity=Severity.CRITICAL,
                    title=f"Log Audit Failure — '{name}' claims to clear or disable audit logging",
                    description=(
                        f"Tool '{name}' description indicates it can wipe or disable the audit trail: "
                        f"'{m.group()}'."
                    ),
                    tool_name=name,
                    evidence=description[:300],
                    remediation=(
                        "Do not expose log-deletion or log-disabling operations through the MCP surface."
                    ),
                )]

        # HIGH: tool exposes raw log data (audit logs contain credentials, PII, internal paths)
        if _HIGH_NAME.search(name):
            return [Finding(
                owasp_category=OWASPCategory.MCP10_LOG_AUDIT,
                severity=Severity.HIGH,
                title=f"Log Audit Failure — '{name}' exposes raw log data",
                description=(
                    f"Tool '{name}' provides access to raw log data. Audit and access logs "
                    "commonly contain credentials, session tokens, internal paths, and PII."
                ),
                tool_name=name,
                remediation=(
                    "Restrict log-access tools to authorised principals only. "
                    "Redact or mask sensitive fields before returning log data via MCP."
                ),
            )]

        for pattern in _HIGH_DESC:
            m = pattern.search(description)
            if m:
                return [Finding(
                    owasp_category=OWASPCategory.MCP10_LOG_AUDIT,
                    severity=Severity.HIGH,
                    title=f"Log Audit Failure — '{name}' exposes log content",
                    description=(
                        f"Tool '{name}' description indicates it returns log data: '{m.group()}'. "
                        "Log data frequently contains sensitive fields."
                    ),
                    tool_name=name,
                    evidence=description[:300],
                    remediation=(
                        "Apply field-level masking before returning log entries through MCP. "
                        "Restrict log access to authenticated, authorised callers."
                    ),
                )]

        # MEDIUM: logging explicitly stated as absent (unaudited tool calls)
        for pattern in _MEDIUM_DESC:
            m = pattern.search(description)
            if m:
                return [Finding(
                    owasp_category=OWASPCategory.MCP10_LOG_AUDIT,
                    severity=Severity.MEDIUM,
                    title=f"Log Audit Failure — '{name}' operates without audit logging",
                    description=(
                        f"Tool '{name}' description indicates logging is disabled or absent: "
                        f"'{m.group()}'. Unlogged tool calls cannot be audited or attributed."
                    ),
                    tool_name=name,
                    evidence=description[:300],
                    remediation="Enable structured audit logging for all tool invocations.",
                )]

        return []

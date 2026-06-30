from __future__ import annotations

import re
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

# inputSchema field names that indicate credential harvesting (HIGH)
_HIGH_SCHEMA_RE = re.compile(
    r"password|secret|jwt|(?:api|auth|access|signing)[_\-]?key"
    r"|credential|private[_\-]?key|passphrase|client[_\-]?secret",
    re.I,
)

# inputSchema field names that indicate PII collection (MEDIUM)
_MEDIUM_SCHEMA_RE = re.compile(
    r"\bssn\b|social[_\-]?security|credit[_\-]?card"
    r"|medical[_\-]?record|driver[_\-]?licen|passport|date[_\-]?of[_\-]?birth|bank[_\-]?account",
    re.I,
)

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

# D5: tools that dump environment variables — always HIGH (env vars contain secrets)
_ENV_DUMP_TOOL_RE = re.compile(
    r"^(get|list|dump|show|print|export)[_-](env|environment|env_vars|environ)$",
    re.I,
)

# D1: write-side path traversal — param names that accept file paths for writing
_WRITE_PATH_PARAM_RE = re.compile(
    r"\b(filename|file_name|file_path|output_path|output_file|save_to|save_path|dest|destination)\b",
    re.I,
)

# D1: description keywords that confirm write intent (conjugations included)
_WRITE_INTENT_RE = re.compile(
    r"\b(saves?|writes?|creates?\s+file|exports?|output\s+to|writes?\s+to|dumps?\s+to|stores?\s+to)\b",
    re.I,
)

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
            schema_result = self._check_schema(tool.name, tool.input_schema)
            if schema_result:
                findings.append(schema_result)
            traversal_result = self._check_write_traversal(tool.name, tool.description, tool.input_schema)
            if traversal_result:
                findings.append(traversal_result)
        return findings

    def _check(self, name: str, description: str) -> Finding | None:
        # HIGH: environment variable dump — env vars commonly contain API keys and secrets
        if _ENV_DUMP_TOOL_RE.match(name):
            return Finding(
                owasp_category=OWASPCategory.MCP02_SCOPE_CREEP,
                severity=Severity.HIGH,
                title=f"Scope Creep — '{name}' exposes environment variable dump",
                description=(
                    f"Tool '{name}' name matches a pattern associated with environment variable "
                    "enumeration. Environment variables commonly contain API keys, credentials, "
                    "and configuration secrets that should never be exposed through an MCP tool."
                ),
                tool_name=name,
                evidence=description[:300] or None,
                remediation=(
                    "Remove this tool from the MCP surface entirely, or restrict it to returning "
                    "only non-sensitive variables using an explicit allowlist."
                ),
                confidence=85,
            )

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

    def _check_schema(self, name: str, input_schema: dict[str, Any]) -> Finding | None:
        properties = input_schema.get("properties", {})
        if not isinstance(properties, dict) or not properties:
            return None

        high_fields = [f for f in properties if _HIGH_SCHEMA_RE.search(f)]
        medium_fields = [f for f in properties if _MEDIUM_SCHEMA_RE.search(f) and f not in high_fields]

        if high_fields:
            return Finding(
                owasp_category=OWASPCategory.MCP02_SCOPE_CREEP,
                severity=Severity.HIGH,
                title=f"Scope Creep — '{name}' inputSchema requests credential fields",
                description=(
                    f"Tool '{name}' inputSchema declares field(s) associated with credentials "
                    f"or secrets: {', '.join(high_fields)}. This may indicate the tool harvests "
                    "authentication material from the LLM caller."
                ),
                tool_name=name,
                evidence=f"inputSchema properties: {', '.join(high_fields)}",
                remediation=(
                    "Do not accept raw credentials as tool input parameters. "
                    "Use secure credential stores and reference by identifier, not value."
                ),
                confidence=80,
            )

        if medium_fields:
            return Finding(
                owasp_category=OWASPCategory.MCP02_SCOPE_CREEP,
                severity=Severity.MEDIUM,
                title=f"Scope Creep — '{name}' inputSchema requests PII fields",
                description=(
                    f"Tool '{name}' inputSchema declares field(s) associated with PII: "
                    f"{', '.join(medium_fields)}. Collecting PII through MCP tools may violate "
                    "data minimization principles and privacy regulations."
                ),
                tool_name=name,
                evidence=f"inputSchema properties: {', '.join(medium_fields)}",
                remediation=(
                    "Review whether collecting this PII is strictly necessary. "
                    "Apply data minimization and ensure appropriate consent and handling."
                ),
                confidence=70,
            )

        return None

    def _check_write_traversal(
        self, name: str, description: str, input_schema: dict[str, Any]
    ) -> Finding | None:
        """D1: flag tools that accept file path params AND describe write operations.

        Allows detecting write-side path traversal risks statically — before dynamic testing.
        """
        if not description or not _WRITE_INTENT_RE.search(description):
            return None

        properties = input_schema.get("properties", {}) if input_schema else {}
        write_path_fields = [f for f in properties if _WRITE_PATH_PARAM_RE.search(f)]
        if not write_path_fields:
            return None

        return Finding(
            owasp_category=OWASPCategory.MCP02_SCOPE_CREEP,
            severity=Severity.HIGH,
            title=f"Scope Creep — '{name}' accepts write-path param (path traversal risk)",
            description=(
                f"Tool '{name}' accepts a file path parameter ({', '.join(write_path_fields)}) "
                "and its description indicates write operations. Without path sanitization, "
                "callers may supply traversal sequences to write files outside the intended directory."
            ),
            tool_name=name,
            evidence=f"path param(s): {', '.join(write_path_fields)} | description: {description[:200]}",
            remediation=(
                "Validate and canonicalize file path inputs. Restrict writes to an explicit "
                "base directory using path.resolve() or os.path.abspath() checks. "
                "Manual verification recommended."
            ),
            confidence=65,
        )

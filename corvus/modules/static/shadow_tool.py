from __future__ import annotations

import re

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

# Tools whose exact name matches a dangerous built-in or high-value target
_EXACT_HIGH: frozenset[str] = frozenset({
    # Shells / execution
    "bash", "sh", "zsh", "fish", "pwsh", "powershell", "cmd",
    "execute", "exec", "run", "eval", "system", "subprocess", "terminal",
    # Common MCP file/editor tool names (Anthropic Claude built-ins)
    "str_replace_based_edit_tool", "create_file", "read_file",
    "write_file", "edit_file", "delete_file",
    # Computer-use
    "computer", "computer_use",
    # Common agent tool names
    "run_command", "execute_command", "shell_exec", "shell_command",
})

# Patterns that flag tools as MEDIUM regardless of exact name
_MEDIUM_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(shell|bash|exec|terminal|powershell|cmd)\b", re.I),
    re.compile(r"\b(delete|wipe|destroy|purge|nuke|remove)\b", re.I),
    re.compile(r"\b(admin|root|sudo|superuser|privilege)\b", re.I),
    re.compile(r"\b(override|bypass|disable|unrestrict|unlock)\b", re.I),
    re.compile(r"\b(exfil|exfiltrate|exfiltration)\b", re.I),
]

# Patterns that flag tools as LOW (suspicious naming style)
_LOW_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^__\w+__$"),   # dunder names signal internal API impersonation
    re.compile(r"^_[a-z]"),     # underscore-private naming
]


# Keywords in descriptions that reveal intent to execute arbitrary system commands
_DANGEROUS_DESCRIPTION = re.compile(
    r"\b(executes?|runs?\s+(shell|command|script|code)|subprocess|os\.system|eval\s*\(|popen)\b",
    re.I,
)

# Scope qualifier phrases that limit a tool to a specific context — reduces severity
_SCOPE_QUALIFIER_RE = re.compile(
    r"\b(only|restricted?\s+to|scoped?\s+to|within\s+the|inside\s+the|limited?\s+to|specific(ally)?)\b",
    re.I,
)

# DB-tool name prefixes — tools with these prefixes legitimately use execution language in docs
_DB_TOOL_PREFIX_RE = re.compile(
    r"^(pg_|mysql_|mongo_|sqlite_|redis_|elastic_|dynamo_|psql_|db_)",
    re.I,
)


class ShadowToolModule(ScanModule):
    owasp_id = "EXT03"
    category = "Shadow Tool Detection"
    name = "shadow-tool"
    description = (
        "Detects tool names that shadow common built-ins or signal dangerous operations, "
        "enabling namespace squatting or trust hijacking"
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
            findings.extend(self._check(tool.name, tool.description or ""))
            findings.extend(self._check_description(tool.name, tool.description))
        return findings

    def _check_description(self, name: str, description: str) -> list[Finding]:
        if description and _DANGEROUS_DESCRIPTION.search(description):
            # DB-prefix tools legitimately use execution language in their descriptions
            # (e.g. pg_execute_sql "Executes arbitrary SQL"). Still flag but at lower severity.
            if _DB_TOOL_PREFIX_RE.match(name):
                return [Finding(
                    owasp_category=OWASPCategory.EXT03_SHADOW_TOOL,
                    severity=Severity.MEDIUM,
                    title=f"Shadow Tool — '{name}' (DB tool) description reveals execution intent",
                    description=(
                        f"Tool '{name}' description contains execution keywords. "
                        "DB-prefixed tools legitimately execute queries, but verify the scope "
                        "is restricted to the intended database context."
                    ),
                    tool_name=name,
                    evidence=description[:300],
                    remediation=(
                        "Declare the allowed SQL operation types in the schema and reject "
                        "statements outside the declared scope (e.g. no DDL if tool is DQL only)."
                    ),
                    confidence=60,
                )]
            return [Finding(
                owasp_category=OWASPCategory.EXT03_SHADOW_TOOL,
                severity=Severity.HIGH,
                title=f"Shadow Tool — '{name}' description reveals arbitrary execution intent",
                description=(
                    f"Tool '{name}' description contains keywords associated with arbitrary "
                    "command or shell execution. This may enable sandbox escape or privilege escalation."
                ),
                tool_name=name,
                evidence=description[:300],
                remediation=(
                    "Restrict the tool to a well-defined, scoped operation. "
                    "Do not expose generic shell execution capabilities via MCP tools."
                ),
                confidence=80,
            )]
        return []

    def _check(self, name: str, description: str = "") -> list[Finding]:
        found: list[Finding] = []

        if name.lower() in _EXACT_HIGH:
            # If the description declares a scope qualifier, the tool is restricted —
            # downgrade from HIGH to MEDIUM (e.g. 'read_file' limited to .docx files)
            has_scope = bool(description and _SCOPE_QUALIFIER_RE.search(description))
            severity = Severity.MEDIUM if has_scope else Severity.HIGH
            title_suffix = " (scope-restricted)" if has_scope else " conflicts with a high-value built-in name"
            found.append(Finding(
                owasp_category=OWASPCategory.EXT03_SHADOW_TOOL,
                severity=severity,
                title=f"Shadow Tool — '{name}'{title_suffix}",
                description=(
                    f"Tool '{name}' uses a name commonly associated with built-in or "
                    "high-privilege operations. A malicious server could register this tool "
                    "to shadow legitimate tools and intercept LLM actions."
                ),
                tool_name=name,
                remediation=(
                    "Rename the tool to something unique and context-specific. "
                    "Avoid generic names like 'bash', 'execute', or 'read_file' that clash "
                    "with well-known tool namespaces."
                ),
                confidence=90 if not has_scope else 70,
            ))
            return found  # no need to check further patterns for the same tool

        for pattern in _MEDIUM_PATTERNS:
            if pattern.search(name):
                found.append(Finding(
                    owasp_category=OWASPCategory.EXT03_SHADOW_TOOL,
                    severity=Severity.MEDIUM,
                    title=f"Shadow Tool — '{name}' contains a dangerous operation keyword",
                    description=(
                        f"Tool name '{name}' matches a pattern associated with privileged or "
                        "destructive operations. Verify this tool's scope is appropriate."
                    ),
                    tool_name=name,
                    remediation="Use precise, scoped tool names that reflect the exact operation performed.",
                    confidence=85,
                ))
                return found

        for pattern in _LOW_PATTERNS:
            if pattern.search(name):
                found.append(Finding(
                    owasp_category=OWASPCategory.EXT03_SHADOW_TOOL,
                    severity=Severity.LOW,
                    title=f"Shadow Tool — '{name}' uses a suspicious naming convention",
                    description=(
                        f"Tool name '{name}' follows a naming convention (dunder or "
                        "underscore-prefixed) that may attempt to impersonate internal APIs."
                    ),
                    tool_name=name,
                    remediation="Use plain, descriptive tool names without special prefixes or suffixes.",
                    confidence=70,
                ))
                return found

        return found

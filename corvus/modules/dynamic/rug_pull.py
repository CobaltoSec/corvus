from __future__ import annotations

import re
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity, ToolSpec
from ...core.session import ScanSession
from ...transport.base import MCPTransport


# Tool names that suggest by-design stateful behavior (e.g. server-sequential-thinking)
_STATEFUL_TOOL_NAME = re.compile(
    r"sequential_thinking|memory|session|context|chain|state|history|thread",
    re.I,
)


class RugPullModule(ScanModule):
    owasp_id = "MCP06"
    category = "Rug Pull"
    name = "rug-pull"
    description = (
        "Re-enumerates the server surface after dynamic testing and diffs against the "
        "initial snapshot to detect tools added, removed, or mutated during the session"
    )
    is_static = False

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        new_tools = await _list_tools(transport)

        # Stateful servers (e.g. server-sequential-thinking) may return an empty tool
        # list mid-session because they reset internal state — not a rug pull.
        if len(new_tools) == 0 and len(surface.tools) > 0:
            return []

        orig_map = {t.name: t for t in surface.tools}
        new_map = {t.name: t for t in new_tools}
        orig_names = set(orig_map)
        new_names = set(new_map)

        findings: list[Finding] = []

        # Tools that appeared after the session started
        for name in sorted(new_names - orig_names):
            findings.append(Finding(
                owasp_category=OWASPCategory.MCP06_RUG_PULL,
                severity=Severity.CRITICAL,
                title=f"Rug Pull — tool '{name}' appeared mid-session",
                description=(
                    f"Tool '{name}' was not present during initial enumeration but appeared "
                    "after the session began. This is a classic rug-pull indicator: the server "
                    "may have established trust before introducing a malicious tool."
                ),
                tool_name=name,
                confidence=90,
                remediation=(
                    "Never trust a server whose tool surface changes during an active session. "
                    "Re-enumerate before any privileged operations."
                ),
            ))

        # Tools that disappeared during the session
        for name in sorted(orig_names - new_names):
            # B5: stateful servers legitimately hide tools based on context
            is_stateful = bool(_STATEFUL_TOOL_NAME.search(name))
            findings.append(Finding(
                owasp_category=OWASPCategory.MCP06_RUG_PULL,
                severity=Severity.LOW if is_stateful else Severity.HIGH,
                title=f"Rug Pull — tool '{name}' disappeared mid-session",
                description=(
                    f"Tool '{name}' was present at session start but is no longer listed. "
                    + ("Tool name suggests stateful by-design behavior — low confidence finding."
                       if is_stateful else
                       "The server may be hiding evidence of malicious tool calls.")
                ),
                tool_name=name,
                confidence=40 if is_stateful else 85,
                remediation="Treat disappearing tools as a red flag and audit all prior interactions.",
            ))

        # Tools whose descriptions changed (highest-impact mutation)
        for name in sorted(orig_names & new_names):
            orig_t = orig_map[name]
            new_t = new_map[name]

            if orig_t.description != new_t.description:
                findings.append(Finding(
                    owasp_category=OWASPCategory.MCP06_RUG_PULL,
                    severity=Severity.CRITICAL,
                    title=f"Rug Pull — description of '{name}' changed mid-session",
                    description=(
                        f"Tool '{name}' description was mutated after the session started. "
                        "Attackers use this to inject hidden instructions after the LLM has "
                        "already decided to trust the tool."
                    ),
                    tool_name=name,
                    evidence=f"Before: {orig_t.description[:200]!r}\nAfter:  {new_t.description[:200]!r}",
                    confidence=90,
                    remediation=(
                        "Pin tool descriptions at session start and reject any mid-session mutation. "
                        "Re-initialize from scratch if a change is detected."
                    ),
                ))

            elif orig_t.input_schema != new_t.input_schema:
                findings.append(Finding(
                    owasp_category=OWASPCategory.MCP06_RUG_PULL,
                    severity=Severity.MEDIUM,
                    title=f"Rug Pull — schema of '{name}' changed mid-session",
                    description=(
                        f"The input schema for tool '{name}' changed after session start. "
                        "This may alter what inputs the tool accepts, bypassing pre-session validation."
                    ),
                    tool_name=name,
                    confidence=80,
                    remediation="Pin schemas at session start; treat schema drift as untrusted.",
                ))

        return findings


async def _list_tools(transport: MCPTransport) -> list[ToolSpec]:
    try:
        result: Any = await transport.send_request("tools/list") or {}
        return [
            ToolSpec(
                name=t["name"],
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {}),
            )
            for t in result.get("tools", [])
        ]
    except Exception:
        return []

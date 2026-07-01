"""elicitation_probe.py — MCP elicitation/create phishing probe (EXT09)."""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

_ELICITATION_READ_TIMEOUT = 3.0
_DRAIN_TIMEOUT = 0.4
_MAX_TOOLS_TO_PROBE = 5

# Phishing patterns in elicitation message content
_PHISHING_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(enter|provide|type|input)\s+(your\s+)?(password|secret|credential|token|api\s*key|private\s*key|passphrase)", re.I), "credential phishing"),
    (re.compile(r"(confirm|enter)\s+(your\s+)?(username\s+and\s+password|login\s+credential)", re.I), "login phishing"),
    (re.compile(r"(your\s+)?(github|aws|google|azure|openai)\s+(token|key|secret|credential)", re.I), "service credential phishing"),
    (re.compile(r"(security\s+code|verification\s+code|2fa\s+code|mfa\s+code|otp)", re.I), "2FA phishing"),
    (re.compile(r"(do\s+not\s+share|keep\s+this\s+(secret|private))\s+but\s+(enter|provide)", re.I), "social engineering"),
]

_SENSITIVE_SCHEMA_RE = re.compile(
    r'"(password|secret|token|credential|apiKey|api_key|privateKey|private_key)"',
    re.I,
)

_ELICITATION_DESC_RE = re.compile(
    r"\b(ask\s+(?:the\s+)?user|prompt\s+(?:the\s+)?user|elicit|user\s+input|user\s+confirmation|request\s+input)\b",
    re.I,
)


async def _send_raw_and_collect(
    transport: MCPTransport,
    request: dict[str, Any],
    timeout: float,
) -> list[dict[str, Any]]:
    """Write a JSON-RPC request directly to stdin and collect ALL stdout messages."""
    if not (hasattr(transport, "_process") and transport._process is not None):
        return []

    payload = (json.dumps(request) + "\n").encode()
    try:
        transport._process.stdin.write(payload)
        await transport._process.stdin.drain()
    except Exception:
        return []

    messages: list[dict[str, Any]] = []
    read_timeout = timeout
    while True:
        try:
            line = await asyncio.wait_for(
                transport._process.stdout.readline(),
                timeout=read_timeout,
            )
        except asyncio.TimeoutError:
            break
        if not line:
            break
        try:
            obj = json.loads(line.decode(errors="replace"))
            messages.append(obj)
            read_timeout = _DRAIN_TIMEOUT
        except (json.JSONDecodeError, ValueError):
            continue
        except Exception:
            break
    return messages


def _analyze_elicitation_request(tool_name: str, params: dict[str, Any]) -> Finding:
    """Classify a captured elicitation/create request by severity."""
    raw_json = json.dumps(params)
    message = str(params.get("message", ""))
    schema_str = json.dumps(params.get("requestedSchema", {}))

    # Check phishing patterns in the message
    for pattern, label in _PHISHING_PATTERNS:
        if pattern.search(message):
            return Finding(
                owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
                severity=Severity.CRITICAL,
                title=f"Elicitation phishing — '{tool_name}' solicits {label}",
                description=(
                    f"Tool '{tool_name}' triggered elicitation/create with a message "
                    f"matching phishing pattern '{label}'. The server is attempting to "
                    "collect sensitive credentials from the user disguised as a "
                    "legitimate system prompt."
                ),
                tool_name=tool_name,
                payload=raw_json[:300],
                evidence=f"Phishing pattern '{label}' in elicitation message: {message[:200]!r}",
                exploitation_confirmed=True,
                confidence=88,
                remediation=(
                    "Never request passwords, tokens, or API keys via elicitation/create. "
                    "Elicitation should only request non-sensitive clarification input."
                ),
            )

    # Check for sensitive field names in the schema
    if _SENSITIVE_SCHEMA_RE.search(schema_str):
        sensitive_fields = _SENSITIVE_SCHEMA_RE.findall(schema_str)
        return Finding(
            owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
            severity=Severity.HIGH,
            title=f"Elicitation schema requests sensitive fields — '{tool_name}'",
            description=(
                f"Tool '{tool_name}' triggered elicitation/create with a schema "
                f"requesting sensitive fields: {sensitive_fields}. "
                "Collecting credentials via elicitation bypasses secure storage "
                "and exposes them to the MCP server."
            ),
            tool_name=tool_name,
            payload=raw_json[:300],
            evidence=f"Sensitive fields in requestedSchema: {sensitive_fields}",
            confidence=82,
            remediation=(
                "Remove sensitive field names (password, token, secret, api_key) "
                "from elicitation schemas. Use secure credential storage instead."
            ),
        )

    # Unsolicited elicitation — no obvious phishing, but still suspicious
    return Finding(
        owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
        severity=Severity.MEDIUM,
        title=f"Unsolicited elicitation request — '{tool_name}' calls elicitation/create",
        description=(
            f"Tool '{tool_name}' triggered elicitation/create. "
            "No obvious phishing patterns were found in the message or schema, "
            "but unsolicited user input requests deserve manual review."
        ),
        tool_name=tool_name,
        payload=raw_json[:300],
        evidence=f"elicitation/create triggered by tools/call({tool_name!r}): {message[:100]!r}",
        confidence=65,
        remediation=(
            "Review why this tool needs user input via elicitation. "
            "Ensure the message is benign and the schema requests only non-sensitive data."
        ),
    )


class ElicitationProbeModule(ScanModule):
    owasp_id = "EXT09"
    category = "Elicitation Phishing"
    name = "elicitation-probe"
    description = (
        "Detects malicious use of MCP elicitation/create: phishing for credentials, "
        "sensitive schema fields, and unsolicited user input requests."
    )
    is_static = False

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Static: tool descriptions that hint at elicitation usage
        hint_tools = [t.name for t in surface.tools if _ELICITATION_DESC_RE.search(t.description)]
        if hint_tools:
            findings.append(Finding(
                owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
                severity=Severity.LOW,
                title="Tool descriptions suggest user-input elicitation behavior",
                description=(
                    "Tool descriptions mention asking or prompting the user for input "
                    f"(ask user, prompt user, elicit): {hint_tools}. "
                    "Servers that use elicitation/create can request sensitive data "
                    "from users without their informed consent."
                ),
                evidence=", ".join(hint_tools),
                confidence=40,
                remediation=(
                    "Review tools that use elicitation/create. "
                    "Ensure they only request non-sensitive, task-relevant input."
                ),
            ))

        # Dynamic probes only on stdio transport
        is_stdio = hasattr(transport, "_process") and transport._process is not None
        if not is_stdio:
            return findings

        # Re-initialize declaring elicitation capability
        re_init = {
            "jsonrpc": "2.0", "id": 8700, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"elicitation": {}},
                "clientInfo": {"name": "corvus-elicitation-probe", "version": "0.1.0"},
            },
        }
        await _send_raw_and_collect(transport, re_init, timeout=2.0)

        notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        notif_payload = (json.dumps(notif) + "\n").encode()
        try:
            transport._process.stdin.write(notif_payload)
            await transport._process.stdin.drain()
        except Exception:
            return findings

        # Probe tools with no required params
        no_req = [t for t in surface.tools if not t.input_schema.get("required")]
        to_probe = no_req[:_MAX_TOOLS_TO_PROBE]

        for i, tool in enumerate(to_probe):
            req = {
                "jsonrpc": "2.0", "id": 8750 + i,
                "method": "tools/call",
                "params": {"name": tool.name, "arguments": {}},
            }
            messages = await _send_raw_and_collect(transport, req, timeout=_ELICITATION_READ_TIMEOUT)
            for msg in messages:
                if msg.get("method") == "elicitation/create":
                    findings.append(_analyze_elicitation_request(tool.name, msg.get("params", {})))
                    break

        return findings

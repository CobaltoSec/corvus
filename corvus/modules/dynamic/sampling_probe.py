"""sampling_probe.py — MCP sampling/createMessage injection probe (EXT08)."""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

_SAMPLING_READ_TIMEOUT = 3.0
_DRAIN_TIMEOUT = 0.4
_MAX_TOOLS_TO_PROBE = 5

_INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.I), "prompt override"),
    (re.compile(r"\bsystem\s*:\s*[^\n]{5}", re.I), "system-role injection"),
    (re.compile(r"you\s+are\s+now\s+(?!a\s+helpful)", re.I), "persona hijack"),
    (re.compile(r"\bassistant\s*:\s*[^\n]{5}", re.I), "fake assistant turn"),
    (re.compile(r"output\s+your\s+(system\s+prompt|instructions?)", re.I), "system-prompt exfil"),
    (re.compile(r"<INST>|<SYS>|\[INST\]|\[SYS\]", re.I), "LLM-template injection"),
    (re.compile(r"###\s*(Human|Assistant|System)\s*:", re.I), "chat-template injection"),
]

_CONTEXT_EXFIL_RE = re.compile(r'"includeContext"\s*:\s*"(allServers|thisServer)"')

_SAMPLING_DESC_RE = re.compile(
    r"\b(ask\s+(?:the\s+)?(?:AI|LLM|model|claude|gpt)|"
    r"generat(?:e|ing)\s+(?:via|using|with)\s+(?:AI|LLM|model)|"
    r"\bsampling\b|createMessage|llm\s+call)\b",
    re.I,
)


def _extract_text_content(params: dict[str, Any]) -> str:
    """Flatten all text from sampling/createMessage params into one string."""
    parts: list[str] = []
    if sp := params.get("systemPrompt"):
        parts.append(str(sp))
    for msg in params.get("messages", []):
        content = msg.get("content", {})
        if isinstance(content, dict) and content.get("type") == "text":
            parts.append(content.get("text", ""))
        elif isinstance(content, str):
            parts.append(content)
    return " ".join(parts)


async def _send_raw_and_collect(
    transport: MCPTransport,
    request: dict[str, Any],
    timeout: float,
) -> list[dict[str, Any]]:
    """Write a JSON-RPC request directly to stdin and collect ALL stdout messages.

    Matches the batch_dos direct-bypass pattern: writes to _process.stdin,
    reads from _process.stdout until timeout.  Returns every parsed JSON object.
    """
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
            # After first message drain remaining quickly
            read_timeout = _DRAIN_TIMEOUT
        except (json.JSONDecodeError, ValueError):
            continue
        except Exception:
            break
    return messages


def _analyze_sampling_request(tool_name: str, params: dict[str, Any]) -> Finding:
    """Classify a captured sampling/createMessage by severity."""
    raw_json = json.dumps(params)
    text = _extract_text_content(params)

    if _CONTEXT_EXFIL_RE.search(raw_json):
        ctx = params.get("includeContext", "")
        return Finding(
            owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
            severity=Severity.HIGH,
            title=f"Sampling context exfiltration — '{tool_name}' requests includeContext={ctx!r}",
            description=(
                f"Tool '{tool_name}' triggered sampling/createMessage with "
                f"includeContext={ctx!r}. This causes the LLM host to attach "
                "the full conversation context from other MCP servers, enabling "
                "cross-server data exfiltration without user consent."
            ),
            tool_name=tool_name,
            payload=raw_json[:300],
            evidence=f"includeContext={ctx!r} in sampling/createMessage",
            confidence=85,
            remediation=(
                "Do not set includeContext to 'allServers' or 'thisServer' "
                "unless explicitly user-consented and documented."
            ),
        )

    for pattern, label in _INJECTION_PATTERNS:
        if pattern.search(text):
            return Finding(
                owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
                severity=Severity.CRITICAL,
                title=f"Sampling injection — '{tool_name}' injects {label} via createMessage",
                description=(
                    f"Tool '{tool_name}' triggered sampling/createMessage containing "
                    f"injection patterns ({label}). The server can hijack the LLM host "
                    "by injecting arbitrary system prompts or fake conversation turns."
                ),
                tool_name=tool_name,
                payload=raw_json[:300],
                evidence=f"Pattern '{label}' in: {text[:200]!r}",
                exploitation_confirmed=True,
                confidence=88,
                remediation=(
                    "Never embed user-controlled or dynamic data in sampling system prompts. "
                    "Validate sampling content against an allowlist."
                ),
            )

    return Finding(
        owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
        severity=Severity.MEDIUM,
        title=f"Unsolicited sampling request — '{tool_name}' calls sampling/createMessage",
        description=(
            f"Tool '{tool_name}' triggered sampling/createMessage. No obvious injection "
            "pattern was found in the prompt content, but unsolicited sampling "
            "deserves manual review — the server is requesting LLM inference "
            "from the host client without user knowledge."
        ),
        tool_name=tool_name,
        payload=raw_json[:300],
        evidence=f"sampling/createMessage triggered by tools/call({tool_name!r})",
        confidence=70,
        remediation=(
            "Review why this tool requires sampling. Ensure prompts are minimal "
            "and do not include sensitive context."
        ),
    )


class SamplingProbeModule(ScanModule):
    owasp_id = "EXT08"
    category = "Sampling Injection"
    name = "sampling-probe"
    description = (
        "Detects malicious use of MCP sampling/createMessage: prompt injection, "
        "context exfiltration via includeContext, and unsolicited sampling requests."
    )
    is_static = False

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Static: tool descriptions that hint at sampling usage
        hint_tools = [t.name for t in surface.tools if _SAMPLING_DESC_RE.search(t.description)]
        if hint_tools:
            findings.append(Finding(
                owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
                severity=Severity.LOW,
                title="Tool descriptions suggest sampling-based behavior",
                description=(
                    "Tool descriptions contain language associated with LLM sampling "
                    f"(ask AI, generate via LLM, createMessage): {hint_tools}. "
                    "Servers that use sampling can inject arbitrary prompts into the host."
                ),
                evidence=", ".join(hint_tools),
                confidence=40,
                remediation=(
                    "Review tools that use sampling/createMessage. "
                    "Sanitize any user-controlled data before including it in sampling prompts."
                ),
            ))

        # Dynamic probes only on stdio transport
        is_stdio = hasattr(transport, "_process") and transport._process is not None
        if not is_stdio:
            return findings

        # Re-initialize declaring sampling capability so server knows it can request sampling
        re_init = {
            "jsonrpc": "2.0", "id": 8800, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"sampling": {}},
                "clientInfo": {"name": "corvus-sampling-probe", "version": "0.1.0"},
            },
        }
        await _send_raw_and_collect(transport, re_init, timeout=2.0)

        # Send initialized notification
        notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        notif_payload = (json.dumps(notif) + "\n").encode()
        try:
            transport._process.stdin.write(notif_payload)
            await transport._process.stdin.drain()
        except Exception:
            return findings

        # Probe tools with no required params (can call them with empty arguments)
        no_req = [t for t in surface.tools if not t.input_schema.get("required")]
        to_probe = no_req[:_MAX_TOOLS_TO_PROBE]

        for i, tool in enumerate(to_probe):
            req = {
                "jsonrpc": "2.0", "id": 8900 + i,
                "method": "tools/call",
                "params": {"name": tool.name, "arguments": {}},
            }
            messages = await _send_raw_and_collect(transport, req, timeout=_SAMPLING_READ_TIMEOUT)
            for msg in messages:
                if msg.get("method") == "sampling/createMessage":
                    findings.append(_analyze_sampling_request(tool.name, msg.get("params", {})))
                    break  # one finding per tool

        return findings

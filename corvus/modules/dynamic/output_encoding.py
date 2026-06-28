from __future__ import annotations

import re
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...payloads.engine import PayloadEngine
from ...transport.base import MCPTransport

# Control chars excluding tab (\x09), newline (\x0a), carriage return (\x0d)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

# Zero-width Unicode: U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+FEFF BOM
_ZERO_WIDTH_CHARS = "".join(chr(c) for c in (0x200B, 0x200C, 0x200D, 0xFEFF))
_ZERO_WIDTH_RE = re.compile(f"[{_ZERO_WIDTH_CHARS}]")

# Bidi overrides: U+202A-U+202E (LRE/RLE/PDF/LRO/RLO) + U+2066-U+2069 (LRI/RLI/FSI/PDI)
_BIDI_CHARS = (
    "".join(chr(c) for c in range(0x202A, 0x202F))
    + "".join(chr(c) for c in range(0x2066, 0x206A))
)
_BIDI_RE = re.compile(f"[{_BIDI_CHARS}]")


class OutputEncodingModule(ScanModule):
    owasp_id = "MCP10"
    category = "Context Injection & Over-Sharing"
    name = "output-encoding"
    description = (
        "Detects tool responses containing invisible or dangerous Unicode: "
        "control characters, zero-width chars, or bidirectional overrides "
        "that can hide malicious content from users or manipulate LLM reasoning"
    )
    is_static = False

    def __init__(self):
        self.engine = PayloadEngine()

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for tool in surface.tools:
            schema = tool.input_schema
            properties: dict[str, Any] = schema.get("properties", {})
            required: list[str] = schema.get("required", [])
            args = {
                p: self.engine.benign_default(s.get("type", "string"))
                for p, s in properties.items()
                if p in required
            }
            try:
                result = await transport.send_request(
                    "tools/call", {"name": tool.name, "arguments": args}
                )
                text = _extract_text(result)
                if not text:
                    continue

                if _CTRL_RE.search(text):
                    matches = _CTRL_RE.findall(text)
                    hex_repr = " ".join(f"\\x{ord(c):02x}" for c in matches[:5])
                    findings.append(Finding(
                        owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
                        severity=Severity.HIGH,
                        title=f"Hidden Control Characters in '{tool.name}' response",
                        description=(
                            f"Tool '{tool.name}' returned control characters "
                            f"({hex_repr}) in its response. "
                            "Null bytes and other control chars can corrupt LLM context, "
                            "hide malicious instructions from display, or exploit "
                            "string-handling bugs in agent pipelines."
                        ),
                        tool_name=tool.name,
                        evidence=f"Control chars: {hex_repr} — preview: {repr(text[:200])}",
                        confidence=90,
                        remediation=(
                            "Strip all non-printable characters before returning tool output. "
                            "Use an allowlist of safe Unicode ranges (printable + whitespace)."
                        ),
                    ))

                if _ZERO_WIDTH_RE.search(text):
                    matches = _ZERO_WIDTH_RE.findall(text)
                    unicode_repr = " ".join(f"U+{ord(c):04X}" for c in matches[:5])
                    findings.append(Finding(
                        owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
                        severity=Severity.HIGH,
                        title=f"Zero-Width Characters in '{tool.name}' response",
                        description=(
                            f"Tool '{tool.name}' returned zero-width Unicode characters "
                            f"({unicode_repr}). "
                            "These chars are invisible to users but visible to LLMs, enabling "
                            "steganographic injection of hidden instructions or covert data "
                            "exfiltration channels that bypass content review."
                        ),
                        tool_name=tool.name,
                        evidence=f"Zero-width chars: {unicode_repr} — preview: {repr(text[:200])}",
                        confidence=90,
                        remediation=(
                            "Reject or strip U+200B/C/D (zero-width space/non-joiner/joiner) "
                            "and U+FEFF (BOM) from all tool output before returning to the LLM."
                        ),
                    ))

                if _BIDI_RE.search(text):
                    matches = _BIDI_RE.findall(text)
                    unicode_repr = " ".join(f"U+{ord(c):04X}" for c in matches[:5])
                    findings.append(Finding(
                        owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
                        severity=Severity.CRITICAL,
                        title=f"Bidirectional Override Characters in '{tool.name}' response",
                        description=(
                            f"Tool '{tool.name}' returned Unicode bidirectional override "
                            f"characters ({unicode_repr}). "
                            "Bidi overrides (RLO/LRO/RLE/LRE) can reverse displayed text to "
                            "deceive users into approving malicious actions — the 'Trojan Source' "
                            "technique. In MCP context this enables UI redressing attacks where "
                            "the LLM sees different content than what the user reviews."
                        ),
                        tool_name=tool.name,
                        evidence=f"Bidi chars: {unicode_repr} — preview: {repr(text[:200])}",
                        confidence=95,
                        remediation=(
                            "Block all Unicode bidirectional override characters "
                            "(U+202A-U+202E, U+2066-U+2069) in tool output. "
                            "These have no legitimate use in structured MCP tool responses."
                        ),
                    ))

            except Exception:
                pass

        return findings


def _extract_text(result: Any) -> str:
    if not result:
        return ""
    content = result.get("content", []) if isinstance(result, dict) else []
    return " ".join(c.get("text", "") for c in content if isinstance(c, dict))

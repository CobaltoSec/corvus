from __future__ import annotations

import base64
import re
import time
from collections import Counter
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...payloads.engine import PayloadEngine
from ...transport.base import MCPTransport

_SIZE_THRESHOLD = 8_192   # bytes — responses larger than this risk flooding LLM context
_TRIGRAM_THRESHOLD = 15   # same 3-word sequence must appear this many times to flag

_B64_RE = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")

# Administrative list tools — returning large config dumps is expected, not a threat
_ADMIN_LIST_TOOL_RE = re.compile(
    r"^get_(whitelist|blacklist|allowlist|blocklist|config|settings)$",
    re.I,
)

# Tools whose names explicitly declare they are slow — timing check would always FP
_SLOW_BY_DESIGN_RE = re.compile(
    r"long[._\-]?running|slow|delay|sleep|wait_for|background|deferred",
    re.I,
)


class ResponseFloodModule(ScanModule):
    owasp_id = "MCP10"
    category = "Context Injection & Over-Sharing"
    name = "response-flood"
    description = (
        "Detects tool responses that are excessively large or contain highly repetitive content "
        "that could overflow an LLM context window or inject looping instructions"
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
            if _ADMIN_LIST_TOOL_RE.match(tool.name):
                continue  # admin config dumps are expected to be large — not a threat
            schema = tool.input_schema
            properties: dict[str, Any] = schema.get("properties", {})
            required: list[str] = schema.get("required", [])
            args = {
                p: self.engine.benign_default(s.get("type", "string"))
                for p, s in properties.items()
                if p in required
            }
            try:
                _t0 = time.monotonic()
                result = await transport.send_request(
                    "tools/call", {"name": tool.name, "arguments": args}
                )
                elapsed = time.monotonic() - _t0
                text = _extract_text(result)

                if elapsed > 10.0 and not _SLOW_BY_DESIGN_RE.search(tool.name):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
                        severity=Severity.MEDIUM,
                        title=f"Slow tool response — '{tool.name}' took {elapsed:.1f}s",
                        description=(
                            f"Tool '{tool.name}' took {elapsed:.1f} seconds to respond. "
                            "Slow responses can be used for resource exhaustion in agent pipelines "
                            "or indicate unbounded computation triggered by benign inputs."
                        ),
                        tool_name=tool.name,
                        evidence=f"Response time: {elapsed:.2f}s",
                        confidence=70,
                        remediation="Enforce server-side timeouts on all tool executions. Cap at 30s max.",
                    ))

                if not text:
                    continue

                byte_size = len(text.encode("utf-8"))

                if byte_size > _SIZE_THRESHOLD:
                    findings.append(Finding(
                        owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
                        severity=Severity.HIGH,
                        title=f"Response Flooding — '{tool.name}' returns oversized response",
                        description=(
                            f"Tool '{tool.name}' returned {byte_size:,} bytes "
                            f"(threshold: {_SIZE_THRESHOLD:,} bytes). "
                            "Large responses can overflow LLM context windows, push out system "
                            "prompts, or cause denial-of-service in agent pipelines."
                        ),
                        tool_name=tool.name,
                        evidence=f"{byte_size:,} bytes — preview: {text[:200]}",
                        confidence=85,
                        remediation=(
                            "Paginate or cap tool responses. Never return unbounded data. "
                            "Aim for responses under 4 KB to preserve LLM context budget."
                        ),
                    ))

                if _is_repetitive(text):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
                        severity=Severity.MEDIUM,
                        title=f"Response Flooding — '{tool.name}' returns highly repetitive content",
                        description=(
                            f"Tool '{tool.name}' response contains a phrase repeated ≥{_TRIGRAM_THRESHOLD} times. "
                            "Repetitive content can be used to anchor specific instructions into "
                            "LLM memory or exhaust context budget with low-information noise."
                        ),
                        tool_name=tool.name,
                        evidence=text[:300],
                        confidence=80,
                        remediation=(
                            "Deduplicate response data. Avoid returning the same value or phrase "
                            "more than a handful of times in a single response."
                        ),
                    ))

                decoded = _check_encoded_payload(text)
                if decoded is not None:
                    findings.append(Finding(
                        owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
                        severity=Severity.MEDIUM,
                        title=f"Response contains large base64-encoded text content — potential covert payload",
                        description=(
                            f"Tool '{tool.name}' response contains a base64-encoded string that "
                            "decodes to readable ASCII text. This technique can be used to smuggle "
                            "hidden instructions past naive content filters."
                        ),
                        tool_name=tool.name,
                        evidence=f"Decoded preview: {decoded[:200]}",
                        confidence=65,
                        remediation=(
                            "Audit tool responses for encoded payloads. "
                            "If base64 output is expected, document and scope it explicitly."
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


def _check_encoded_payload(text: str) -> str | None:
    """Return decoded content if a large base64 string decodes to readable ASCII."""
    for m in _B64_RE.finditer(text):
        try:
            decoded = base64.b64decode(m.group(0) + "==").decode("ascii")
            if len(decoded) > len(m.group(0)) * 0.7 and decoded.isprintable():
                return decoded[:200]
        except Exception:
            continue
    return None


def _is_repetitive(text: str) -> bool:
    """Return True if any 3-word sequence appears suspiciously often."""
    words = text.split()
    if len(words) < 30:
        return False
    trigrams = Counter(" ".join(words[i:i + 3]) for i in range(len(words) - 2))
    if not trigrams:
        return False
    most_common_count = trigrams.most_common(1)[0][1]
    return most_common_count >= _TRIGRAM_THRESHOLD

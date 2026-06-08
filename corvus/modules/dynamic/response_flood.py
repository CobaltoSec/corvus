from __future__ import annotations

from collections import Counter
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...payloads.engine import PayloadEngine
from ...transport.base import MCPTransport

_SIZE_THRESHOLD = 8_192   # bytes — responses larger than this risk flooding LLM context
_TRIGRAM_THRESHOLD = 15   # same 3-word sequence must appear this many times to flag


class ResponseFloodModule(ScanModule):
    owasp_id = "MCP07"
    category = "Response Flooding"
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

                byte_size = len(text.encode("utf-8"))

                if byte_size > _SIZE_THRESHOLD:
                    findings.append(Finding(
                        owasp_category=OWASPCategory.MCP07_RESPONSE_FLOOD,
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
                        remediation=(
                            "Paginate or cap tool responses. Never return unbounded data. "
                            "Aim for responses under 4 KB to preserve LLM context budget."
                        ),
                    ))

                if _is_repetitive(text):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.MCP07_RESPONSE_FLOOD,
                        severity=Severity.MEDIUM,
                        title=f"Response Flooding — '{tool.name}' returns highly repetitive content",
                        description=(
                            f"Tool '{tool.name}' response contains a phrase repeated ≥{_TRIGRAM_THRESHOLD} times. "
                            "Repetitive content can be used to anchor specific instructions into "
                            "LLM memory or exhaust context budget with low-information noise."
                        ),
                        tool_name=tool.name,
                        evidence=text[:300],
                        remediation=(
                            "Deduplicate response data. Avoid returning the same value or phrase "
                            "more than a handful of times in a single response."
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

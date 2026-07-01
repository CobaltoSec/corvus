from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...payloads.engine import PayloadEngine
from ...transport.base import MCPTransport

# --- Web-tool heuristic -------------------------------------------------
# Tools expected to return arbitrary external content (fetch, browse, search).
# For these tools only Tier-1 signals fire, and at lower confidence.

# Name check: split on _ / - so "fetch_url" → {"fetch", "url"}
_WEB_KEYWORDS_NAME = frozenset({
    "fetch", "browse", "navigate", "crawl", "scrape", "download",
    "web", "search", "webpage", "website", "browser", "puppeteer", "playwright",
    "url", "http",
})

# Description check: no word boundaries — "Navigates" matches "navigat"
_WEB_DESC_RE = re.compile(
    r"fetch|browse|navigat|crawl|scrape|download|"
    r"web.?search|search.?web|http.?get|webpage|website|browser|puppeteer|playwright",
    re.I,
)

# --- LLM-instruction delimiter injection (CRITICAL, always) -------------
# Fake system/instruction blocks planted in tool output.
_DELIMITER_RE = re.compile(
    r"(\[SYSTEM\]|\[INST\]|<\|system\|>|<\|im_start\|>\s*system"
    r"|###\s*SYSTEM\s*(OVERRIDE|PROMPT)|<system>)",
    re.I,
)


@dataclass
class _Signal:
    pattern: re.Pattern[str]
    label: str
    severity_nonweb: Severity
    confidence_nonweb: int
    severity_web: Severity | None  # None = skip for web tools
    confidence_web: int


_SIGNALS: list[_Signal] = [
    # Tier 1 — fire on all tools (lower confidence for web tools)
    _Signal(
        re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions?", re.I),
        "ignore-previous-instructions",
        Severity.HIGH, 90,
        Severity.MEDIUM, 65,
    ),
    _Signal(
        re.compile(r"disregard\s+(your|all|previous|prior)", re.I),
        "disregard-instructions",
        Severity.HIGH, 88,
        Severity.MEDIUM, 60,
    ),
    _Signal(
        re.compile(r"forget\s+(all\s+)?(your\s+)?(previous\s+)?instructions?", re.I),
        "forget-instructions",
        Severity.HIGH, 88,
        Severity.MEDIUM, 60,
    ),
    _Signal(
        re.compile(r"override\s+your\s+(instructions?|system\s+prompt|rules?|guidelines?)", re.I),
        "override-system-prompt",
        Severity.HIGH, 90,
        Severity.MEDIUM, 65,
    ),
    # Tier 2 — non-web tools only
    _Signal(
        re.compile(r"\byou\s+are\s+now\b", re.I),
        "persona-override",
        Severity.MEDIUM, 75,
        None, 0,
    ),
    _Signal(
        re.compile(r"\bas\s+a\s+new\s+AI\b", re.I),
        "as-a-new-ai",
        Severity.MEDIUM, 80,
        None, 0,
    ),
    _Signal(
        re.compile(r"\byour\s+true\s+purpose\s+is\b", re.I),
        "true-purpose-hijack",
        Severity.HIGH, 85,
        None, 0,
    ),
    _Signal(
        re.compile(r"\bdo\s+not\s+follow\s+your\b", re.I),
        "do-not-follow",
        Severity.HIGH, 85,
        None, 0,
    ),
    _Signal(
        re.compile(r"\bnew\s+instructions?\s*:", re.I),
        "new-instructions-marker",
        Severity.MEDIUM, 75,
        None, 0,
    ),
    _Signal(
        re.compile(r"\byou\s+must\s+now\b", re.I),
        "you-must-now",
        Severity.MEDIUM, 70,
        None, 0,
    ),
]

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _is_web_tool(tool_name: str, description: str) -> bool:
    name_parts = set(re.split(r"[_\-\s]+", tool_name.lower()))
    if name_parts & _WEB_KEYWORDS_NAME:
        return True
    return bool(_WEB_DESC_RE.search(description))


def _extract_text(result: Any) -> str:
    if not isinstance(result, dict):
        return ""
    content = result.get("content", [])
    return " ".join(c.get("text", "") for c in content if isinstance(c, dict))


def _scan_text(text: str, is_web: bool) -> list[tuple[str, Severity, int]]:
    """Return list of (label, severity, confidence) for all matches."""
    matches: list[tuple[str, Severity, int]] = []
    text_scan = text[:16_384]  # cap to avoid perf issues on large responses

    # Delimiter injection — always CRITICAL
    if _DELIMITER_RE.search(text_scan):
        m = _DELIMITER_RE.search(text_scan)
        matches.append((f"LLM-delimiter-injection ({m.group(0)!r})", Severity.CRITICAL, 95))

    # Phrase signals
    for sig in _SIGNALS:
        m = sig.pattern.search(text_scan)
        if not m:
            continue
        if is_web:
            if sig.severity_web is None:
                continue
            matches.append((sig.label, sig.severity_web, sig.confidence_web))
        else:
            matches.append((sig.label, sig.severity_nonweb, sig.confidence_nonweb))

    return matches


class ResponseInjectionModule(ScanModule):
    owasp_id = "MCP10"
    category = "Context Injection & Over-Sharing"
    name = "response-injection"
    description = (
        "Calls each tool with benign args and scans the response for LLM-directive "
        "language (prompt injection phrases, fake system blocks). "
        "Web/fetch tools are checked at lower confidence; non-web tools at full confidence."
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
            except Exception:
                continue

            text = _extract_text(result)
            if not text:
                continue

            is_web = _is_web_tool(tool.name, tool.description or "")
            matches = _scan_text(text, is_web)
            if not matches:
                continue

            # Pick highest severity match as primary
            matches.sort(key=lambda t: _SEV_ORDER.index(t[1]))
            primary_label, primary_sev, primary_conf = matches[0]
            all_labels = ", ".join(m[0] for m in matches)
            snippet = repr(text[:300])

            web_note = " (web/fetch tool — lower confidence due to external content)" if is_web else ""

            findings.append(Finding(
                owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
                severity=primary_sev,
                title=f"Prompt Injection via Response — '{tool.name}' [{primary_label}]",
                description=(
                    f"Tool '{tool.name}' returned a response containing LLM-directive "
                    f"language: {all_labels}.{web_note} "
                    "This indicates the server may be planting adversarial instructions "
                    "into the LLM context via tool output (OWASP MCP10)."
                ),
                tool_name=tool.name,
                evidence=f"signals={all_labels} — snippet: {snippet}",
                remediation=(
                    "Audit the data source feeding this tool's response. "
                    "Sanitize or reject tool output containing LLM instruction syntax "
                    "before returning it to the agent context."
                ),
                confidence=primary_conf,
            ))

        return findings

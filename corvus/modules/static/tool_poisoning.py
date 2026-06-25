from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

import yaml

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

_PATTERNS_FILE = Path(__file__).parent.parent.parent / "payloads" / "data" / "poisoning_patterns.yaml"


class ToolPoisoningModule(ScanModule):
    owasp_id = "MCP03"
    category = "Tool Poisoning"
    name = "tool-poisoning"
    description = "Detects hidden instructions and obfuscation in tool descriptions"
    is_static = True

    def __init__(self):
        with open(_PATTERNS_FILE) as f:
            data = yaml.safe_load(f)
        self._patterns = [re.compile(p, re.IGNORECASE) for p in data["regex_patterns"]]
        self._unicode = data["unicode_suspicious"]
        self._max_len = data.get("max_description_length", 1000)
        self._entropy_threshold = data.get("high_entropy_threshold", 5.0)
        self._min_entropy_length = data.get("min_entropy_length", 200)

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for tool in surface.tools:
            findings.extend(self._check_tool(tool.name, tool.description))
        return findings

    def _check_tool(self, tool_name: str, description: str) -> list[Finding]:
        found: list[Finding] = []

        # Regex injection patterns
        for pattern in self._patterns:
            m = pattern.search(description)
            if m:
                found.append(Finding(
                    owasp_category=OWASPCategory.MCP03_TOOL_POISONING,
                    severity=Severity.CRITICAL,
                    title=f"Tool Poisoning — hidden instruction in '{tool_name}'",
                    description=f"Description matches injection pattern: '{m.group()}'",
                    tool_name=tool_name,
                    evidence=description[:300],
                    remediation="Remove any LLM-directed instructions from tool descriptions.",
                    confidence=85,
                ))
                break

        # Suspicious unicode
        for char in self._unicode:
            if char in description:
                found.append(Finding(
                    owasp_category=OWASPCategory.MCP03_TOOL_POISONING,
                    severity=Severity.HIGH,
                    title=f"Tool Poisoning — invisible unicode in '{tool_name}'",
                    description=f"Description contains suspicious character U+{ord(char):04X}",
                    tool_name=tool_name,
                    evidence=f"Character U+{ord(char):04X} at position {description.index(char)}",
                    remediation="Strip all zero-width and directional override unicode characters.",
                    confidence=90,
                ))
                break

        # Excessive length
        if len(description) > self._max_len:
            found.append(Finding(
                owasp_category=OWASPCategory.MCP03_TOOL_POISONING,
                severity=Severity.MEDIUM,
                title=f"Excessive description length in '{tool_name}'",
                description=f"Description is {len(description)} chars (limit {self._max_len}). May contain hidden content.",
                tool_name=tool_name,
                remediation="Keep descriptions concise; review for hidden instructions.",
                confidence=80,
            ))

        # High entropy (possible obfuscation) — only fires on descriptions long enough
        # to rule out naturally random short identifiers
        if len(description) > self._min_entropy_length and _entropy(description) > self._entropy_threshold:
            found.append(Finding(
                owasp_category=OWASPCategory.MCP03_TOOL_POISONING,
                severity=Severity.LOW,
                title=f"High entropy description in '{tool_name}'",
                description="Unusual character distribution may indicate obfuscated content.",
                tool_name=tool_name,
                remediation="Review description for base64-encoded or otherwise obfuscated payloads.",
                confidence=20,
            ))

        return found


def _entropy(text: str) -> float:
    freq = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())

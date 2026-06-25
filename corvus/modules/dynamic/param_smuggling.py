from __future__ import annotations

import json
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...payloads.engine import PayloadEngine
from ...transport.base import MCPTransport

# Extra parameters to inject alongside valid args
_SMUGGLE_PARAMS: list[dict[str, Any]] = [
    {"_debug": True},
    {"unsafe": True},
    {"admin": True},
    {"verbose": True},
    {"__proto__": {"polluted": True}},
    {"bypass": True},
    {"raw": True},
]


class ParamSmugglingModule(ScanModule):
    owasp_id = "EXT01"
    category = "Schema Validation Bypass"
    name = "param-smuggling"
    description = (
        "Tests each tool by appending undeclared hidden parameters and compares responses "
        "to detect behavior differences that suggest server-side privilege escalation"
    )
    is_static = False

    def __init__(self) -> None:
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

            benign_args = {
                p: self.engine.benign_default(s.get("type", "string"))
                for p, s in properties.items()
                if p in required
            }

            # Baseline response
            try:
                baseline_result = await transport.send_request(
                    "tools/call", {"name": tool.name, "arguments": benign_args}
                )
            except Exception:
                continue  # can't establish baseline — skip tool

            for extra in _SMUGGLE_PARAMS:
                probe_args = {**benign_args, **extra}
                try:
                    probe_result = await transport.send_request(
                        "tools/call", {"name": tool.name, "arguments": probe_args}
                    )
                    diff = _response_diff(baseline_result, probe_result)
                    if diff:
                        severity, confidence, desc = _classify_diff(diff, extra)
                        findings.append(Finding(
                            owasp_category=OWASPCategory.EXT01_SCHEMA_BYPASS,
                            severity=severity,
                            title=f"Hidden param accepted — '{tool.name}' responds differently to {list(extra.keys())[0]}",
                            description=desc,
                            tool_name=tool.name,
                            payload=json.dumps(extra),
                            evidence=f"Diff: {diff[:300]}",
                            confidence=confidence,
                            remediation=(
                                "Set additionalProperties: false in the tool schema and reject unknown parameters. "
                                "Validate all inputs against a strict allowlist."
                            ),
                        ))
                        break  # one finding per tool is sufficient
                except Exception:
                    pass

        return findings


def _response_diff(baseline: Any, probe: Any) -> str:
    """Return a human-readable description of the difference, or empty string if none."""
    b_text = _extract_text(baseline)
    p_text = _extract_text(probe)

    if b_text == p_text:
        return ""

    # Structural difference: different JSON keys
    try:
        b_data = json.loads(b_text)
        p_data = json.loads(p_text)
        if isinstance(b_data, dict) and isinstance(p_data, dict):
            new_keys = set(p_data) - set(b_data)
            if new_keys:
                return f"New JSON keys in probe response: {sorted(new_keys)}"
    except (json.JSONDecodeError, ValueError):
        pass

    # Size difference: significantly more content in probe response
    b_len, p_len = len(b_text), len(p_text)
    if p_len > b_len * 1.5 and p_len - b_len > 50:
        return f"Probe response significantly larger: {b_len} → {p_len} chars"

    # Different error vs. success
    b_err = isinstance(baseline, dict) and baseline.get("isError")
    p_err = isinstance(probe, dict) and probe.get("isError")
    if b_err != p_err:
        return f"isError changed: baseline={b_err} probe={p_err}"

    return ""


def _classify_diff(diff: str, extra: dict[str, Any]) -> tuple[Severity, int, str]:
    param = list(extra.keys())[0]
    if "New JSON keys" in diff or "isError changed" in diff:
        return (
            Severity.HIGH, 75,
            f"Parameter '{param}' caused a structural change in the response, "
            "suggesting the server processed it as a privileged flag. " + diff,
        )
    return (
        Severity.MEDIUM, 55,
        f"Parameter '{param}' caused a response size or format change. "
        "The server may be accepting undeclared parameters. " + diff,
    )


def _extract_text(result: Any) -> str:
    if not result:
        return ""
    content = result.get("content", []) if isinstance(result, dict) else []
    return " ".join(c.get("text", "") for c in content if isinstance(c, dict))

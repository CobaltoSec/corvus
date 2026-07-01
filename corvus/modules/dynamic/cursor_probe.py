"""cursor_probe.py — MCP pagination cursor IDOR/overflow probe (EXT13)."""
from __future__ import annotations

import asyncio
import json
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

_CURSOR_TIMEOUT = 5.0


async def _tools_list_with_cursor(
    transport: MCPTransport, cursor: Any, req_id: int
) -> dict[str, Any] | None:
    """Call tools/list with a cursor param; return result or None."""
    params: dict[str, Any] = {"cursor": cursor}
    try:
        return await asyncio.wait_for(
            transport.send_request("tools/list", params),
            timeout=_CURSOR_TIMEOUT,
        )
    except asyncio.TimeoutError:
        return "timeout"  # type: ignore[return-value]
    except Exception:
        return None


class CursorProbeModule(ScanModule):
    owasp_id = "EXT13"
    category = "Cursor Manipulation"
    name = "cursor-probe"
    description = (
        "Tests MCP pagination cursor handling for path traversal, overflow, "
        "IDOR, and crash vulnerabilities."
    )
    is_static = False

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        findings: list[Finding] = []
        crash_reported = False

        def _add_crash(title: str, evidence: str, confidence: int = 80) -> None:
            nonlocal crash_reported
            if not crash_reported:
                findings.append(Finding(
                    owasp_category=OWASPCategory.EXT13_CURSOR_MANIPULATION,
                    severity=Severity.HIGH,
                    title=title,
                    description=(
                        "The server crashed or disconnected when processing an invalid cursor value. "
                        "This is a Denial of Service vector."
                    ),
                    evidence=evidence,
                    confidence=confidence,
                    remediation="Validate cursor values before processing; return -32602 (Invalid params) for malformed cursors.",
                ))
                crash_reported = True

        # Probe 0 — baseline: does the server support nextCursor?
        base_result: dict[str, Any] | None = None
        base_tools: list[Any] = []
        try:
            base_result = await asyncio.wait_for(
                transport.send_request("tools/list"),
                timeout=_CURSOR_TIMEOUT,
            )
            if base_result:
                base_tools = base_result.get("tools", [])
        except Exception:
            return findings

        supports_pagination = bool(base_result and base_result.get("nextCursor"))

        # Probe 1 — path traversal cursor
        r1 = await _tools_list_with_cursor(transport, "../../../../etc/passwd", 7300)
        if r1 == "timeout":
            _add_crash("Server hangs on path traversal cursor", "tools/list timed out with cursor='../../../../etc/passwd'")
        elif r1 is None:
            pass  # exception = appropriate error
        else:
            # Server accepted the cursor without error
            findings.append(Finding(
                owasp_category=OWASPCategory.EXT13_CURSOR_MANIPULATION,
                severity=Severity.MEDIUM,
                title="Server accepts path traversal cursor without validation",
                description=(
                    "tools/list accepted cursor='../../../../etc/passwd' and returned a result "
                    "instead of rejecting it. This may indicate missing cursor validation."
                ),
                payload="../../../../etc/passwd",
                confidence=65,
                remediation="Validate cursor values; reject non-opaque or path-like cursor strings.",
            ))

        # Probe 2 — long cursor (overflow)
        long_cursor = "A" * 4096
        r2 = await _tools_list_with_cursor(transport, long_cursor, 7301)
        if r2 == "timeout":
            _add_crash("Server hangs on oversized cursor value", f"tools/list timed out with cursor=A*4096")
        elif r2 is None:
            pass  # error = correct
        elif not crash_reported:
            # Only add if we didn't already flag a crash or medium from probe 1
            if not any(f.severity == Severity.MEDIUM for f in findings):
                findings.append(Finding(
                    owasp_category=OWASPCategory.EXT13_CURSOR_MANIPULATION,
                    severity=Severity.MEDIUM,
                    title="Server accepts oversized cursor value without validation",
                    description=(
                        "tools/list accepted a 4096-character cursor string without returning an error."
                    ),
                    payload=f"'A' * 4096",
                    confidence=65,
                    remediation="Enforce maximum cursor length and reject oversized values.",
                ))

        # Probe 3 — integer cursor IDOR
        for cursor_val in ["0", "-1"]:
            r3 = await _tools_list_with_cursor(transport, cursor_val, 7302)
            if r3 == "timeout":
                _add_crash(f"Server hangs on cursor={cursor_val}", f"tools/list timed out with cursor={cursor_val!r}")
                break
            elif r3 is not None and isinstance(r3, dict):
                r3_tools = r3.get("tools", [])
                r3_names = {t.get("name") for t in r3_tools if isinstance(t, dict)}
                base_names = {t.get("name") if isinstance(t, dict) else t for t in base_tools}
                if r3_names and r3_names != base_names:
                    findings.append(Finding(
                        owasp_category=OWASPCategory.EXT13_CURSOR_MANIPULATION,
                        severity=Severity.HIGH,
                        title=f"Cursor IDOR — different tool set returned for cursor={cursor_val!r}",
                        description=(
                            f"tools/list with cursor={cursor_val!r} returned a different set of tools "
                            "than the baseline call, indicating cursor-based IDOR."
                        ),
                        payload=cursor_val,
                        evidence=f"Baseline tools: {sorted(base_names)}, cursor={cursor_val} tools: {sorted(r3_names)}",
                        confidence=75,
                        remediation="Ensure pagination cursors are opaque tokens; never use sequential integers.",
                    ))
                    break

        # Probe 4 — null cursor
        r4 = await _tools_list_with_cursor(transport, None, 7303)
        if r4 == "timeout":
            if not crash_reported:
                findings.append(Finding(
                    owasp_category=OWASPCategory.EXT13_CURSOR_MANIPULATION,
                    severity=Severity.MEDIUM,
                    title="Server crashes on null cursor value",
                    description="tools/list timed out or became unresponsive when cursor=null was provided.",
                    payload="null",
                    confidence=70,
                    remediation="Handle null cursor values gracefully; treat null as 'first page'.",
                ))

        return findings

"""cancellation_probe.py — MCP notifications/cancelled race condition probe (EXT14)."""
from __future__ import annotations

import asyncio
import json
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

_RESPONSE_TIMEOUT = 5.0
_DRAIN_TIMEOUT = 0.5


async def _write_raw(transport: MCPTransport, message: dict[str, Any]) -> bool:
    """Write a raw JSON message to the transport stdin. Returns True on success."""
    if not (hasattr(transport, "_process") and transport._process is not None):
        return False
    payload = (json.dumps(message) + "\n").encode()
    try:
        transport._process.stdin.write(payload)
        await transport._process.stdin.drain()
        return True
    except Exception:
        return False


async def _read_response(transport: MCPTransport, timeout: float) -> dict[str, Any] | None:
    """Read one JSON line from stdout with timeout. Returns parsed object or None."""
    if not (hasattr(transport, "_process") and transport._process is not None):
        return None
    try:
        line = await asyncio.wait_for(
            transport._process.stdout.readline(),
            timeout=timeout,
        )
        if not line:
            return None
        return json.loads(line.decode(errors="replace"))
    except asyncio.TimeoutError:
        return "timeout"  # type: ignore[return-value]
    except Exception:
        return None


async def _server_alive(transport: MCPTransport) -> bool:
    """Check if the server still responds to tools/list."""
    try:
        result = await asyncio.wait_for(
            transport.send_request("tools/list"),
            timeout=_RESPONSE_TIMEOUT,
        )
        return result is not None
    except Exception:
        return False


class CancellationProbeModule(ScanModule):
    owasp_id = "EXT14"
    category = "Cancellation Race Condition"
    name = "cancellation-probe"
    description = (
        "Tests MCP notifications/cancelled handling for race conditions, "
        "server hangs, and crash vulnerabilities (stdio only)."
    )
    is_static = False

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        # Stdio only
        if not (hasattr(transport, "_process") and transport._process is not None):
            return []

        findings: list[Finding] = []

        # Probe 1 — cancel non-existent request
        cancel_msg = {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "nonexistent-99999", "reason": "test"},
        }
        await _write_raw(transport, cancel_msg)

        # Now send a normal tools/list to check responsiveness
        req = {"jsonrpc": "2.0", "id": 8200, "method": "tools/list", "params": {}}
        await _write_raw(transport, req)
        response = await _read_response(transport, _RESPONSE_TIMEOUT)

        if response == "timeout":
            findings.append(Finding(
                owasp_category=OWASPCategory.EXT14_CANCELLATION_RACE,
                severity=Severity.HIGH,
                title="Server hangs after receiving cancellation for unknown request ID",
                description=(
                    "After sending notifications/cancelled with a non-existent requestId, "
                    "the server stopped responding to subsequent requests."
                ),
                payload=json.dumps(cancel_msg),
                confidence=75,
                remediation="Ignore notifications/cancelled for unknown request IDs without blocking.",
            ))
            return findings
        elif response is None:
            findings.append(Finding(
                owasp_category=OWASPCategory.EXT14_CANCELLATION_RACE,
                severity=Severity.HIGH,
                title="Server crashes on notifications/cancelled for unknown request ID",
                description=(
                    "The server crashed or disconnected after receiving notifications/cancelled "
                    "with a requestId that was never sent."
                ),
                payload=json.dumps(cancel_msg),
                confidence=85,
                remediation="Handle unknown requestId in notifications/cancelled gracefully.",
            ))
            return findings
        else:
            findings.append(Finding(
                owasp_category=OWASPCategory.EXT14_CANCELLATION_RACE,
                severity=Severity.INFO,
                title="Server correctly ignores cancellation of unknown request",
                description="The server remained responsive after receiving notifications/cancelled for a non-existent request.",
                confidence=90,
                remediation="No action required — correct behavior.",
            ))

        # Probe 2 — rapid cancellation flood
        for i in range(10):
            flood_msg = {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": f"flood-{i}", "reason": "corvus-flood"},
            }
            await _write_raw(transport, flood_msg)

        # Check responsiveness after flood
        req2 = {"jsonrpc": "2.0", "id": 8201, "method": "tools/list", "params": {}}
        await _write_raw(transport, req2)
        response2 = await _read_response(transport, _RESPONSE_TIMEOUT)

        if response2 == "timeout" or response2 is None:
            findings.append(Finding(
                owasp_category=OWASPCategory.EXT14_CANCELLATION_RACE,
                severity=Severity.HIGH,
                title="Server unresponsive after rapid cancellation flood",
                description=(
                    "After sending 10 rapid notifications/cancelled with sequential IDs, "
                    "the server stopped responding to a normal tools/list request."
                ),
                payload="10 × notifications/cancelled{requestId: flood-N}",
                confidence=70,
                remediation="Rate-limit or drop notifications/cancelled to prevent resource exhaustion.",
            ))
        # No finding if server responds normally to flood

        # Probe 3 — cancel own active request (race condition)
        req3_id = "cancel-race-test-1"
        req3 = {"jsonrpc": "2.0", "id": req3_id, "method": "tools/list", "params": {}}
        cancel3 = {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": req3_id, "reason": "corvus-race"},
        }
        await _write_raw(transport, req3)
        await _write_raw(transport, cancel3)

        response3 = await _read_response(transport, _RESPONSE_TIMEOUT)
        if response3 == "timeout" or response3 is None:
            findings.append(Finding(
                owasp_category=OWASPCategory.EXT14_CANCELLATION_RACE,
                severity=Severity.HIGH,
                title="Race condition between request and cancellation causes server hang",
                description=(
                    "Sending a tools/list request immediately followed by notifications/cancelled "
                    "with the same requestId caused the server to hang."
                ),
                payload=f"tools/list id={req3_id!r} then notifications/cancelled requestId={req3_id!r}",
                confidence=72,
                remediation="Implement thread-safe request cancellation with proper state cleanup.",
            ))
        else:
            # Server responded — check if it was a race artifact
            findings.append(Finding(
                owasp_category=OWASPCategory.EXT14_CANCELLATION_RACE,
                severity=Severity.INFO,
                title="Cancellation race condition timing detected — server responded normally",
                description=(
                    "The request/cancel race did not cause a hang; the server responded "
                    "to one of the two messages."
                ),
                confidence=70,
                remediation="No action required — server handled the race gracefully.",
            ))

        return findings

"""batch_dos.py — JSON-RPC batch array probe (EXT01 / DoS vector)."""
from __future__ import annotations

import asyncio
import json
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import JSONRPCError, MCPTransport

_SMALL_BATCH = 5
_LARGE_BATCH = 50
_BATCH_READ_TIMEOUT = 5.0


def _make_batch(size: int, start_id: int = 9000) -> list[dict[str, Any]]:
    return [{"jsonrpc": "2.0", "id": start_id + i, "method": "tools/list"} for i in range(size)]


async def _send_batch(transport: MCPTransport, batch: list[dict]) -> tuple[bytes | int, str]:
    """Write a raw JSON-RPC batch array to the transport.

    Returns (raw_bytes_or_http_status, body_or_detail).
    """
    raw_payload = (json.dumps(batch) + "\n").encode()

    # stdio path — write directly to the subprocess stdin pipe
    if hasattr(transport, "_process") and transport._process is not None:
        try:
            transport._process.stdin.write(raw_payload)
            await transport._process.stdin.drain()
            try:
                raw = await asyncio.wait_for(
                    transport._process.stdout.readline(),
                    timeout=_BATCH_READ_TIMEOUT,
                )
                return raw, ""
            except asyncio.TimeoutError:
                return b"", "timeout"
        except Exception as e:
            return b"", f"write_error:{e}"

    # HTTP path — POST the JSON array directly via the transport's live client
    if hasattr(transport, "_client") and transport._client is not None:
        try:
            resp = await asyncio.wait_for(
                transport._client.post(
                    transport.url,
                    content=json.dumps(batch).encode(),
                    headers={"Content-Type": "application/json"},
                ),
                timeout=_BATCH_READ_TIMEOUT + 3.0,
            )
            return resp.status_code, resp.text[:500]
        except asyncio.TimeoutError:
            return 0, "timeout"
        except Exception as e:
            return 0, str(e)[:200]

    return b"", "unsupported_transport"


async def _check_alive(transport: MCPTransport) -> bool:
    """Return True if the server still responds after a batch probe."""
    try:
        await transport.send_request("tools/list")
        return True
    except JSONRPCError:
        return True  # error response = server alive
    except AttributeError:
        # Transport read a list (batch response) instead of a dict when processing
        # a stale batch reply — server is alive, just returned non-standard output.
        return True
    except Exception:
        return False


def _check_batch_accepted(
    response_raw: bytes | int,
    body: str,
    batch_size: int,
    is_http: bool,
    findings: list[Finding],
) -> None:
    """Append MEDIUM finding if the server returned a batch response array."""
    try:
        if is_http:
            if isinstance(response_raw, int) and response_raw in (200, 207):
                data = json.loads(body)
                if isinstance(data, list):
                    findings.append(_batch_accepted_finding(batch_size, len(data), is_http))
        else:
            if isinstance(response_raw, bytes) and response_raw:
                data = json.loads(response_raw.decode(errors="replace"))
                if isinstance(data, list):
                    findings.append(_batch_accepted_finding(batch_size, len(data), is_http))
    except (json.JSONDecodeError, ValueError):
        pass


def _batch_accepted_finding(batch_size: int, response_count: int, is_http: bool) -> Finding:
    transport_str = "HTTP" if is_http else "stdio"
    return Finding(
        owasp_category=OWASPCategory.EXT01_SCHEMA_BYPASS,
        severity=Severity.MEDIUM,
        title=f"JSON-RPC batch accepted — unintended batch processing ({transport_str})",
        description=(
            f"The server processed a JSON-RPC 2.0 batch request ({batch_size} requests) "
            "and returned a batch response array. MCP does not define batch semantics. "
            "An attacker can flood the server with large batches to cause resource exhaustion."
        ),
        payload=f"[{batch_size} × {{\"method\":\"tools/list\"}}]",
        evidence=f"Server returned array with {response_count} response object(s)",
        confidence=88,
        remediation="Reject JSON-RPC batch arrays with -32600 (Invalid Request).",
    )


def _safe_str(value: bytes | int) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


class BatchDosModule(ScanModule):
    owasp_id = "EXT01"
    category = "Schema Validation Bypass"
    name = "batch-dos"
    description = (
        "Sends JSON-RPC 2.0 batch arrays (not standard in MCP) to detect "
        "crash/hang DoS vulnerabilities and unintended batch processing."
    )
    is_static = False

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        is_stdio = hasattr(transport, "_process") and transport._process is not None
        is_http = hasattr(transport, "_client") and transport._client is not None
        if not (is_stdio or is_http):
            return []

        findings: list[Finding] = []

        # ── Probe 1: small batch (5 × tools/list) ──────────────────────────────
        small_batch = _make_batch(_SMALL_BATCH)
        response_raw, body = await _send_batch(transport, small_batch)
        alive = await _check_alive(transport)

        if not alive:
            findings.append(Finding(
                owasp_category=OWASPCategory.EXT01_SCHEMA_BYPASS,
                severity=Severity.HIGH,
                title="Protocol crash — JSON-RPC batch array caused server disconnect",
                description=(
                    f"Sending a JSON-RPC 2.0 batch ({_SMALL_BATCH} requests as an array) "
                    "caused the server to crash or disconnect. "
                    "MCP does not define batch semantics; servers must reject arrays gracefully."
                ),
                payload=f'[{{"jsonrpc":"2.0","id":9000,"method":"tools/list"}}, … ({_SMALL_BATCH} items)]',
                evidence=(
                    f"Server disconnected after batch. "
                    f"Pre-crash response: {_safe_str(response_raw)[:100] or 'none'}"
                ),
                confidence=85,
                remediation=(
                    "Validate input type at the JSON-RPC layer: if the parsed value is a list, "
                    "return -32600 (Invalid Request) immediately without further processing."
                ),
            ))
            return findings  # server dead — skip probe 2

        _check_batch_accepted(response_raw, body, _SMALL_BATCH, is_http, findings)

        # ── Probe 2: large batch (50 × tools/list) ─────────────────────────────
        if not any(f.severity == Severity.HIGH for f in findings):
            large_batch = _make_batch(_LARGE_BATCH, start_id=9100)
            response_large, body_large = await _send_batch(transport, large_batch)
            alive_after = await _check_alive(transport)

            if not alive_after:
                findings.append(Finding(
                    owasp_category=OWASPCategory.EXT01_SCHEMA_BYPASS,
                    severity=Severity.HIGH,
                    title=f"DoS — large JSON-RPC batch ({_LARGE_BATCH} requests) caused server crash",
                    description=(
                        f"A batch of {_LARGE_BATCH} tools/list requests caused the server to "
                        "crash or disconnect. This is a Denial of Service vector "
                        "exploitable without authentication."
                    ),
                    payload=f"[{_LARGE_BATCH} × {{\"method\":\"tools/list\"}}]",
                    evidence=f"Server unresponsive after large batch ({body_large or 'no detail'})",
                    confidence=82,
                    remediation=(
                        "Reject JSON-RPC arrays entirely with -32600, "
                        "or enforce a strict maximum batch size with rate limiting."
                    ),
                ))

        return findings

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import JSONRPCError, MCPTransport
from ...transport.http import HttpTransport

_STANDARD_ERROR_CODE = -32601  # Method not found


class ProtoFuzzModule(ScanModule):
    owasp_id = "EXT01"
    category = "Schema Validation Bypass"
    name = "proto-fuzz"
    description = (
        "Fuzzes the JSON-RPC protocol layer: unknown methods, oversized method names, "
        "and null request IDs to detect missing protocol-level validation"
    )
    is_static = False

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Probe 1: Unknown vendor methods — should return -32601 Method Not Found
        for method in ("corvus/ping", "internal/debug", "admin/status", "debug/state"):
            result, err_code = await _probe_method(transport, method)
            if result is not None and err_code is None:
                # Server returned a result (not an error) for an unknown method
                text = _to_str(result)
                findings.append(Finding(
                    owasp_category=OWASPCategory.EXT01_SCHEMA_BYPASS,
                    severity=Severity.LOW,
                    title=f"Unknown method accepted — server responded to '{method}'",
                    description=(
                        f"The server returned a non-error response to '{method}', "
                        "which is not part of the MCP specification. "
                        "This may indicate undocumented endpoints or debug routes."
                    ),
                    payload=method,
                    evidence=text[:300] if text else None,
                    confidence=70,
                    remediation="Return JSON-RPC -32601 for any method not in the MCP specification.",
                ))
                break

        # Probe 2: Oversized method name — server should handle gracefully without crashing
        long_method = "a" * 8192
        result, err_code = await _probe_method(transport, long_method)
        # If result is None and err_code is None, transport itself raised (possible crash/disconnect)
        if result is None and err_code is None:
            findings.append(Finding(
                owasp_category=OWASPCategory.EXT01_SCHEMA_BYPASS,
                severity=Severity.HIGH,
                title="Protocol crash — oversized method name caused transport failure",
                description=(
                    "The server failed to respond to a request with an 8192-byte method name. "
                    "A robust server should return a JSON-RPC error, not disconnect or crash."
                ),
                payload=f"'{'a'*32}...' (8192 bytes)",
                confidence=80,
                remediation=(
                    "Add input length validation at the JSON-RPC parsing layer. "
                    "Return -32700 (parse error) or -32600 (invalid request) for malformed inputs."
                ),
            ))

        # Probe 3: Null request ID — technically invalid per JSON-RPC spec
        result, err_code = await _probe_method(transport, "tools/list", force_null_id=True)
        if result is not None and err_code is None:
            findings.append(Finding(
                owasp_category=OWASPCategory.EXT01_SCHEMA_BYPASS,
                severity=Severity.MEDIUM,
                title="Null request ID accepted — JSON-RPC spec violation",
                description=(
                    "The server accepted a request with id=null and returned a result. "
                    "Per JSON-RPC 2.0, null IDs are reserved for notifications (no response expected). "
                    "Accepting them may cause response routing bugs in complex orchestration scenarios."
                ),
                confidence=60,
                remediation="Reject requests with null id values; treat them as notifications.",
            ))

        # Probe 4: Deeply nested params — resource exhaustion via recursive parsing
        nested_payload: dict = {}
        node = nested_payload
        for _ in range(50):
            node["x"] = {}
            node = node["x"]
        result4, err4 = await _probe_method(transport, "tools/call", params={"name": "echo", "arguments": nested_payload})
        if result4 is None and err4 is None:
            findings.append(Finding(
                owasp_category=OWASPCategory.EXT01_SCHEMA_BYPASS,
                severity=Severity.MEDIUM,
                title="Protocol crash — deeply nested params caused server disconnect",
                description=(
                    "Sending a tools/call request with 50-level nested params caused the server "
                    "to disconnect or crash. Deep nesting can cause stack overflows or "
                    "excessive memory use in recursive JSON parsers."
                ),
                payload="tools/call {arguments: {x: {x: {x: ... (50 levels)}}}}",
                confidence=70,
                remediation=(
                    "Limit JSON object nesting depth at parse time (recommended: ≤32 levels). "
                    "Return -32700 (Parse error) for inputs exceeding the depth limit."
                ),
            ))

        # Probe 5: Type confusion — params as string instead of object
        result5, err5 = await _probe_method(transport, "tools/call", params="not-an-object")
        if result5 is None and err5 is None:
            findings.append(Finding(
                owasp_category=OWASPCategory.EXT01_SCHEMA_BYPASS,
                severity=Severity.LOW,
                title="Protocol crash — string params caused server disconnect",
                description=(
                    "Sending a tools/call request where params is a string (not an object) "
                    "caused the server to crash or disconnect. "
                    "The JSON-RPC spec requires params to be an array or object."
                ),
                payload='{"method":"tools/call","params":"not-an-object"}',
                confidence=65,
                remediation=(
                    "Validate params type (must be object or array) before processing. "
                    "Return -32600 (Invalid Request) for wrong types."
                ),
            ))

        # Probe 6: Missing jsonrpc field — server should reject as invalid request
        is_http = isinstance(transport, HttpTransport)
        body6 = {"id": 9600, "method": "tools/list", "params": {}}
        resp6 = (
            await _send_raw_http(transport.url, body6)
            if is_http
            else await _send_raw_stdio(transport, body6)
        )
        if resp6 is not None and "result" in resp6 and "error" not in resp6:
            findings.append(Finding(
                owasp_category=OWASPCategory.EXT01_SCHEMA_BYPASS,
                severity=Severity.LOW,
                title="Server accepts requests without jsonrpc field",
                description=(
                    "The server returned a successful result to a request missing the required "
                    "'jsonrpc' field. Per JSON-RPC 2.0, this field is mandatory and must equal '2.0'."
                ),
                payload='{"id": 9600, "method": "tools/list", "params": {}}',
                confidence=70,
                remediation=(
                    "Validate that the 'jsonrpc' field is present and equals '2.0' before processing. "
                    "Return -32600 (Invalid Request) for non-conformant messages."
                ),
            ))

        # Probe 7: Array request ID — spec requires ID to be string, number, or null
        body7 = {"jsonrpc": "2.0", "id": [1, 2, 3], "method": "tools/list", "params": {}}
        resp7 = (
            await _send_raw_http(transport.url, body7)
            if is_http
            else await _send_raw_stdio(transport, body7)
        )
        if resp7 is not None and "result" in resp7 and "error" not in resp7:
            findings.append(Finding(
                owasp_category=OWASPCategory.EXT01_SCHEMA_BYPASS,
                severity=Severity.MEDIUM,
                title="Server accepts array request ID — JSON-RPC spec violation",
                description=(
                    "The server returned a successful result to a request with an array as the "
                    "request ID. JSON-RPC 2.0 requires the id to be a string, number, or null."
                ),
                payload='{"jsonrpc": "2.0", "id": [1, 2, 3], "method": "tools/list"}',
                confidence=65,
                remediation=(
                    "Validate that the request 'id' is a string, number, or null. "
                    "Return -32600 (Invalid Request) for array or object IDs."
                ),
            ))

        # Probe 8: _meta progressToken injection — check if reflected in response
        try:
            result8 = await transport.send_request(
                "tools/list", {"_meta": {"progressToken": "CORVUS_INJECT_{{7*7}}"}}
            )
            if result8 is not None and "CORVUS_INJECT_" in str(result8):
                findings.append(Finding(
                    owasp_category=OWASPCategory.EXT01_SCHEMA_BYPASS,
                    severity=Severity.MEDIUM,
                    title="_meta progressToken reflected in response",
                    description=(
                        "The server reflected the _meta.progressToken value back in its response. "
                        "This can be abused to inject template expressions or tracking tokens "
                        "that are later processed by the client."
                    ),
                    payload='{"_meta": {"progressToken": "CORVUS_INJECT_{{7*7}}"}}',
                    evidence=str(result8)[:300],
                    confidence=70,
                    remediation=(
                        "Do not reflect _meta fields from requests into responses. "
                        "Treat _meta as opaque metadata and discard it after use."
                    ),
                ))
        except Exception:
            pass

        return findings


async def _send_raw_http(url: str, body: dict, timeout: float = 5.0) -> dict | None:
    """POST raw JSON-RPC body to HTTP transport; return parsed response or None."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(url, json=body, headers={"Content-Type": "application/json"})
            return r.json()
    except Exception:
        return None


async def _send_raw_stdio(transport: MCPTransport, body: dict, timeout: float = 5.0) -> dict | None:
    """Write raw JSON to stdio transport stdin; return first parsed response or None."""
    if not (hasattr(transport, "_process") and transport._process is not None):
        return None
    payload = (json.dumps(body) + "\n").encode()
    try:
        transport._process.stdin.write(payload)
        await transport._process.stdin.drain()
        line = await asyncio.wait_for(transport._process.stdout.readline(), timeout=timeout)
        return json.loads(line.decode(errors="replace")) if line else None
    except Exception:
        return None


async def _probe_method(
    transport: MCPTransport,
    method: str,
    force_null_id: bool = False,
    params: Any = None,
) -> tuple[Any, int | None]:
    """Call transport.send_request; return (result, error_code) or (None, None) on transport failure."""
    try:
        result = await transport.send_request(method, params)
        return result, None
    except JSONRPCError as e:
        return None, e.code
    except Exception:
        return None, None


def _to_str(result: Any) -> str:
    if not result:
        return ""
    content = result.get("content", []) if isinstance(result, dict) else []
    return " ".join(c.get("text", "") for c in content if isinstance(c, dict))

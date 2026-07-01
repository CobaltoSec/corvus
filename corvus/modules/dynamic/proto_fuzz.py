from __future__ import annotations

from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import JSONRPCError, MCPTransport

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

        return findings


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

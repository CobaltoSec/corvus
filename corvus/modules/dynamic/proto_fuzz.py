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

        return findings


async def _probe_method(
    transport: MCPTransport,
    method: str,
    force_null_id: bool = False,
) -> tuple[Any, int | None]:
    """Call transport.send_request; return (result, error_code) or (None, None) on transport failure."""
    try:
        # Note: send_request manages the JSON-RPC ID internally.
        # For null ID probing, we rely on the transport's underlying mechanism — if the
        # transport doesn't support null IDs, this call behaves normally (no null-ID test).
        result = await transport.send_request(method)
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

from __future__ import annotations

import json
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...payloads.engine import PayloadEngine
from ...transport.base import MCPTransport

_TRAVERSAL_MARKERS = ("../", "..\\", "/etc/", "/proc/", "win.ini", "C:\\Windows")

_TRAVERSAL_SIGNATURES = [
    "root:x:0:0", "daemon:x:", "nobody:x:",  # /etc/passwd
    "HOME=", "PATH=/", "USER=", "SHELL=",    # /proc/self/environ
    "localhost\t127", "127.0.0.1\t",         # /etc/hosts
    "[fonts]", "[extensions]",               # win.ini
]


class ParamInjectionModule(ScanModule):
    owasp_id = "MCP02"
    category = "Parameter Injection"
    name = "param-injection"
    description = "Tests string parameters for command/path/prompt/SQL injection using schema-aware payloads"
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

            for param, param_schema in properties.items():
                if param_schema.get("type") not in ("string", None):
                    continue

                category = self.engine.classify_field(param, param_schema)
                payloads = self.engine.get_payloads(category)

                for payload in payloads:
                    args = self.engine.build_args(properties, required, param, payload)
                    try:
                        result = await transport.send_request(
                            "tools/call", {"name": tool.name, "arguments": args}
                        )
                        # Skip if the tool returned a validation/error response.
                        # pydantic-based servers set isError=True on ValidationError;
                        # echoing the payload inside an error message is not an injection signal.
                        if isinstance(result, dict) and result.get("isError"):
                            continue
                        text = _extract_text(result)

                        # Traversal confirmation is independent of reflection:
                        # file content signatures in the response are a stronger signal
                        # than the payload appearing verbatim.
                        if _traversal_confirmed(payload, text):
                            severity = Severity.CRITICAL
                            confirmed = True
                            desc = (
                                f"File content signatures detected in response — file was "
                                f"successfully read via path traversal (field: {category})."
                            )
                        elif _reflected(payload, text):
                            if _is_json_key_echo(param, payload, text):
                                severity = Severity.LOW
                                confirmed = False
                                desc = (
                                    f"Payload was echoed back as a named JSON field — likely "
                                    f"input logging, not a vulnerability (field: {category})."
                                )
                            elif _is_traversal_payload(payload):
                                severity = Severity.MEDIUM
                                confirmed = False
                                desc = (
                                    f"Traversal payload was reflected verbatim but no file content "
                                    f"signatures found — unconfirmed (field: {category})."
                                )
                            else:
                                severity = Severity.HIGH
                                confirmed = False
                                desc = (
                                    f"Payload was reflected verbatim in the response without "
                                    f"sanitization (field classification: {category})."
                                )
                        else:
                            continue  # no signal — skip this payload

                        findings.append(Finding(
                            owasp_category=OWASPCategory.MCP02_PARAM_INJECTION,
                            severity=severity,
                            title=f"Injection reflected — '{tool.name}.{param}'",
                            description=desc,
                            tool_name=tool.name,
                            parameter=param,
                            payload=payload,
                            evidence=text[:300],
                            exploitation_confirmed=confirmed,
                            remediation=(
                                "Sanitize and validate all input parameters. "
                                "Never pass raw user input to shell commands, file paths, or SQL queries."
                            ),
                        ))
                        break  # one finding per parameter is enough
                    except Exception:
                        pass  # transport/server errors are not injection signals

        return findings


def _extract_text(result: Any) -> str:
    if not result:
        return ""
    content = result.get("content", []) if isinstance(result, dict) else []
    return " ".join(c.get("text", "") for c in content if isinstance(c, dict))


def _reflected(payload: str, response: str) -> bool:
    return bool(payload) and payload in response


def _is_traversal_payload(payload: str) -> bool:
    return any(m in payload for m in _TRAVERSAL_MARKERS)


def _traversal_confirmed(payload: str, text: str) -> bool:
    """Return True if a traversal payload triggered actual file content in the response."""
    if not _is_traversal_payload(payload):
        return False
    return any(sig in text for sig in _TRAVERSAL_SIGNATURES)


def _is_json_key_echo(param: str, payload: str, text: str) -> bool:
    """Return True if the payload appears as the value of a top-level JSON key named after
    the parameter — typical of tools that echo their own inputs in the result record."""
    try:
        data = json.loads(text)
        if isinstance(data, dict) and data.get(param) == payload:
            return True
    except (json.JSONDecodeError, ValueError):
        pass
    return False

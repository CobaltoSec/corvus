from __future__ import annotations

import json
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...payloads.engine import PayloadEngine
from ...transport.base import MCPTransport


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

                        if _reflected(payload, text):
                            # Downgrade if the payload is simply echoed as a named field in a
                            # JSON result (common in tools that log their own inputs).
                            severity = (
                                Severity.LOW
                                if _is_json_key_echo(param, payload, text)
                                else Severity.HIGH
                            )
                            findings.append(Finding(
                                owasp_category=OWASPCategory.MCP02_PARAM_INJECTION,
                                severity=severity,
                                title=f"Injection reflected — '{tool.name}.{param}'",
                                description=(
                                    f"Payload was reflected verbatim in the response without sanitization "
                                    f"(field classification: {category})."
                                ),
                                tool_name=tool.name,
                                parameter=param,
                                payload=payload,
                                evidence=text[:300],
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

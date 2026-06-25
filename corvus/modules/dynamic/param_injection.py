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

# M1: SQL error keywords that confirm exploitation (error-based SQLi)
_SQL_ERROR_SIGNATURES = [
    "sqlite3.OperationalError",
    "pg_exception_detail",
    "SQLSTATE",
    "syntax error near",
    "You have an error in your SQL syntax",
    "ORA-",          # Oracle
    "SQL Server",    # MSSQL
]

# M2: sanitization signals — presence of these in a reflection response means the
# server is explicitly sanitizing/escaping, so the reflection is not exploitable
_SANITIZATION_SIGNALS = ("sanitized", "filtered", "escaped", "blocked")


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
                            confidence = 95
                            desc = (
                                f"File content signatures detected in response — file was "
                                f"successfully read via path traversal (field: {category})."
                            )
                        elif _sql_error_confirmed(text):  # M1: error-based SQLi confirmation
                            severity = Severity.CRITICAL
                            confirmed = True
                            confidence = 92
                            desc = (
                                f"SQL error keywords detected in response — error-based SQLi "
                                f"confirmed (field: {category})."
                            )
                        elif _reflected(payload, text):
                            if _is_json_key_echo(param, payload, text):
                                severity = Severity.LOW
                                confirmed = False
                                confidence = 30
                                desc = (
                                    f"Payload was echoed back as a named JSON field — likely "
                                    f"input logging, not a vulnerability (field: {category})."
                                )
                            elif _is_traversal_payload(payload):
                                severity = Severity.MEDIUM
                                confirmed = False
                                confidence = 50
                                desc = (
                                    f"Traversal payload was reflected verbatim but no file content "
                                    f"signatures found — unconfirmed (field: {category})."
                                )
                            elif _deny_in_context(text):  # M2: explicit sanitization signal
                                severity = Severity.LOW
                                confirmed = False
                                confidence = 30
                                desc = (
                                    f"Payload reflected but response contains sanitization keywords "
                                    f"— server appears to sanitize input (field: {category})."
                                )
                            else:
                                severity = Severity.HIGH
                                confirmed = False
                                confidence = 85
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
                            confidence=confidence,
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


def _sql_error_confirmed(text: str) -> bool:
    """Return True if the response contains a database error keyword (M1)."""
    return any(sig in text for sig in _SQL_ERROR_SIGNATURES)


def _deny_in_context(text: str) -> bool:
    """Return True if the response explicitly signals that sanitization occurred (M2)."""
    lower = text.lower()
    return any(kw in lower for kw in _SANITIZATION_SIGNALS)


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

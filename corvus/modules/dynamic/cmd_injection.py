from __future__ import annotations

import json
import re
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...payloads.engine import PayloadEngine
from ...transport.base import MCPTransport

_TRAVERSAL_MARKERS = (
    "../", "..\\", "/etc/", "/proc/", "win.ini", "C:\\Windows",
    # URL-encoded traversal variants
    "%2e%2e", "..%2f", "..%5c",
)

_TRAVERSAL_SIGNATURES = [
    "root:x:0:0", "daemon:x:", "nobody:x:",  # /etc/passwd
    "HOME=", "PATH=/", "USER=", "SHELL=",    # /proc/self/environ
    "localhost\t127", "127.0.0.1\t",         # /etc/hosts
    "[fonts]", "[extensions]",               # win.ini
]

# M1: SQL error keywords that confirm exploitation (error-based SQLi).
# Must be specific error message patterns — NOT product names like "SQL Server" or
# short tokens like "ORA-" that appear in documentation content (CS03 aws-docs FP).
_SQL_ERROR_SIGNATURES = [
    "sqlite3.OperationalError",
    "pg_exception_detail",
    "SQLSTATE",
    "syntax error near",
    "You have an error in your SQL syntax",
    "ORA-00",        # Oracle error codes (ORA-00001 etc) — more specific than bare "ORA-"
    "Msg 102,",      # MSSQL error format
    "Unclosed quotation mark",  # MSSQL
]

# M2: sanitization signals — presence of these in a reflection response means the
# server is explicitly sanitizing/escaping, so the reflection is not exploitable
_SANITIZATION_SIGNALS = ("sanitized", "filtered", "escaped", "blocked")

# D2: OS-level error messages triggered by traversal payloads — path was used by the OS
_OS_ERROR_SIGNATURES = [
    "ENOENT:",
    "No such file or directory",
    "Permission denied:",
    "IsADirectoryError:",
    "FileNotFoundError:",
]


# B3a: payloads for integer and array params
_INTEGER_PAYLOADS: list[Any] = [0, "0 OR 1=1", "1; DROP TABLE users--", "1 UNION SELECT 1--"]
_ARRAY_PAYLOADS: list[Any] = [["../../etc/passwd"], ["; echo INJECTED #"], ["{{7*7}}"]]

# B5: tool names that are DB operations by design — skip SQL payloads for these
_DB_TOOL_NAME = re.compile(r"write_query|execute_query|run_sql|run_query|exec_sql", re.I)

# A3: common field names where tools legitimately echo back their input (search results, etc.)
_ECHO_FIELD_NAMES = frozenset({
    "query", "search", "q", "term", "filter", "input", "keyword",
    "symbol", "name", "text", "prompt", "request", "pattern",
    "expression", "symbol_name", "class_name", "function_name",
    # Domain-specific echo fields (CS02 calibration — myclaw-toolkit class FPs)
    # These are commonly used as param names in tools that display their input.
    # Note: only add terms that are safe as JSON response keys too (avoids suppressing real injections).
    "color", "coin", "domain", "markdown", "phone", "org", "vs", "format", "param",
})

# Tools whose names suggest they transform input — output always contains the input
_TRANSFORMATION_TOOL_RE = re.compile(
    r"\b(format|convert|transform|encode|decode|render|parse|generate|compile|validate"
    r"|to_html|to_json|to_markdown|to_csv|to_xml|prettify|minify|beautify)\b",
    re.I,
)


class CmdInjectionModule(ScanModule):
    owasp_id = "MCP05"
    category = "Command Injection & Execution"
    name = "cmd-injection"
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

            is_db_tool = bool(_DB_TOOL_NAME.search(tool.name))

            for param, param_schema in properties.items():
                param_type = param_schema.get("type")

                # B3a: handle integer and array params with targeted payloads
                if param_type == "integer":
                    for payload in _INTEGER_PAYLOADS:
                        args = self.engine.build_args(properties, required, param, payload)
                        try:
                            result = await transport.send_request(
                                "tools/call", {"name": tool.name, "arguments": args}
                            )
                            if isinstance(result, dict) and result.get("isError"):
                                continue
                            text = _extract_text(result)
                            if _sql_error_confirmed(text):
                                findings.append(Finding(
                                    owasp_category=OWASPCategory.MCP05_CMD_INJECTION,
                                    severity=Severity.CRITICAL,
                                    title=f"SQL Injection (integer param) — '{tool.name}.{param}'",
                                    description="SQL error keywords in response to integer-typed payload — error-based SQLi confirmed.",
                                    tool_name=tool.name,
                                    parameter=param,
                                    payload=str(payload),
                                    evidence=text[:300],
                                    exploitation_confirmed=True,
                                    confidence=90,
                                    remediation="Use parameterized queries. Never interpolate raw parameter values into SQL strings.",
                                ))
                                break
                        except Exception:
                            pass
                    continue

                if param_type == "array":
                    for payload in _ARRAY_PAYLOADS:
                        args = self.engine.build_args(properties, required, param, payload)
                        try:
                            result = await transport.send_request(
                                "tools/call", {"name": tool.name, "arguments": args}
                            )
                            if isinstance(result, dict) and result.get("isError"):
                                continue
                            text = _extract_text(result)
                            if any(sig in text for sig in _TRAVERSAL_SIGNATURES) or _sql_error_confirmed(text):
                                findings.append(Finding(
                                    owasp_category=OWASPCategory.MCP05_CMD_INJECTION,
                                    severity=Severity.HIGH,
                                    title=f"Injection via array param — '{tool.name}.{param}'",
                                    description="Injection signal detected via array-typed parameter.",
                                    tool_name=tool.name,
                                    parameter=param,
                                    payload=str(payload),
                                    evidence=text[:300],
                                    exploitation_confirmed=True,
                                    confidence=85,
                                    remediation="Validate and sanitize all elements of array parameters individually.",
                                ))
                                break
                        except Exception:
                            pass
                    continue

                if param_type not in ("string", None):
                    continue

                category = self.engine.classify_field(param, param_schema)
                # B5: skip SQL payloads for tools that are DB operations by design
                if is_db_tool and category == "sql":
                    continue
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
                        elif _os_error_traversal_confirmed(payload, text):  # D2: OS used the path
                            severity = Severity.HIGH
                            confirmed = True
                            confidence = 85
                            desc = (
                                f"OS error response to traversal payload — the path was passed "
                                f"to the filesystem (field: {category}). File content not leaked, "
                                f"but path traversal is confirmed."
                            )
                        # M1: error-based SQLi — skip for search/echo fields whose responses
                        # can contain DB error strings as documentation content (CS03 aws-docs FP).
                        elif param.lower() not in _ECHO_FIELD_NAMES and _sql_error_confirmed(text):
                            severity = Severity.CRITICAL
                            confirmed = True
                            confidence = 92
                            desc = (
                                f"SQL error keywords detected in response — error-based SQLi "
                                f"confirmed (field: {category})."
                            )
                        elif _reflected(payload, text):
                            if _is_input_echo(param, payload, text, tool.name):
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

                        # A2: path params that reflect payloads without actual exploitation
                        # are FPs on doc editors and DB servers (e.g. docx-mcp echoes filenames).
                        # Only emit when traversal or OS error is confirmed (exploitation_confirmed).
                        if category == "path" and not confirmed:
                            continue

                        findings.append(Finding(
                            owasp_category=OWASPCategory.MCP05_CMD_INJECTION,
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


def _os_error_traversal_confirmed(payload: str, text: str) -> bool:
    """Return True if a traversal payload triggered an OS filesystem error (D2).

    An OS error means the path reached the filesystem layer — traversal confirmed even
    though file content was not leaked.
    """
    if not _is_traversal_payload(payload):
        return False
    return any(sig in text for sig in _OS_ERROR_SIGNATURES)


def _sql_error_confirmed(text: str) -> bool:
    """Return True if the response contains a database error keyword (M1)."""
    return any(sig in text for sig in _SQL_ERROR_SIGNATURES)


def _deny_in_context(text: str) -> bool:
    """Return True if the response explicitly signals that sanitization occurred (M2)."""
    lower = text.lower()
    return any(kw in lower for kw in _SANITIZATION_SIGNALS)


def _is_input_echo(param: str, payload: str, text: str, tool_name: str = "") -> bool:
    """Return True if the payload appears as an echoed input value in the response.

    Covers four cases:
    - JSON exact match: {"path": "../../etc/passwd", ...}
    - JSON echo field: {"query": "../../etc/passwd", "results": [...]}
    - Plain-text echo: param is a known search/query field and payload appears in response
      (e.g. "No results found for '../../etc/passwd'")
    - Transformation tool: tool name suggests it transforms input (json_formatter, markdown_to_html,
      etc.) — output always contains the input, so reflection is not an injection signal.
    """
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for key, val in data.items():
                if isinstance(val, str) and val == payload:
                    if key == param or key.lower() in _ECHO_FIELD_NAMES:
                        return True
    except (json.JSONDecodeError, ValueError):
        pass

    # Plain-text echo: if the param is a known search/query field, any verbatim
    # appearance of the payload in a plain-text response is likely display echo.
    if param.lower() in _ECHO_FIELD_NAMES and payload in text:
        return True

    # Transformation echo: tool name signals it transforms input into output.
    if tool_name and _TRANSFORMATION_TOOL_RE.search(tool_name) and payload in text:
        return True

    return False

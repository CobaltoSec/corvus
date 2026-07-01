"""prompts_injection.py — MCP prompts/get template injection probe (EXT12)."""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity, PromptSpec
from ...core.session import ScanSession
from ...transport.base import MCPTransport

_PROMPTS_TIMEOUT = 5.0
_MAX_PROMPTS_TO_PROBE = 3

_STATIC_PATTERNS: list[tuple[re.Pattern, Severity, str]] = [
    (re.compile(r"\bignore\s+(all\s+)?previous\s+instructions?\b", re.I), Severity.HIGH, "prompt override injection"),
    (re.compile(r"\bdo not\s+(?:reveal|share|mention)\b", re.I), Severity.MEDIUM, "confidentiality instruction"),
    (re.compile(r"\byou\s+are\s+now\b", re.I), Severity.HIGH, "persona hijack"),
]
_TEMPLATE_LITERAL_RE = re.compile(r"\{\{|\{%")

_INJECT_PAYLOAD = "CORVUS_INJECTION_TEST_{{7*7}}"
_STACK_TRACE_RE = re.compile(r"(Traceback|at line \d+|\.py\", line|stack trace|TypeError|KeyError)", re.I)


def _check_static_prompt(prompt: PromptSpec) -> list[Finding]:
    """Scan a prompt's name and description for static injection patterns."""
    text = f"{prompt.name} {prompt.description}"
    local_findings: list[Finding] = []
    for pattern, severity, label in _STATIC_PATTERNS:
        if pattern.search(text):
            local_findings.append(Finding(
                owasp_category=OWASPCategory.EXT12_PROMPT_INJECTION,
                severity=severity,
                title=f"Static prompt injection pattern in '{prompt.name}' ({label})",
                description=(
                    f"Prompt '{prompt.name}' contains a static injection pattern: {label}. "
                    "This may manipulate how the LLM host processes the prompt."
                ),
                tool_name=prompt.name,
                evidence=f"Pattern '{label}' found in: {text[:200]!r}",
                confidence=80,
                remediation="Remove directive language from prompt names and descriptions.",
            ))
    if _TEMPLATE_LITERAL_RE.search(text):
        local_findings.append(Finding(
            owasp_category=OWASPCategory.EXT12_PROMPT_INJECTION,
            severity=Severity.MEDIUM,
            title=f"Template literal exposure in prompt '{prompt.name}'",
            description=(
                f"Prompt '{prompt.name}' description contains template literal syntax "
                "({{ or {%). This may indicate Jinja2/similar templates leaking into the MCP surface."
            ),
            tool_name=prompt.name,
            evidence=f"Template syntax in: {text[:200]!r}",
            confidence=70,
            remediation="Do not expose server-side template syntax in prompt metadata.",
        ))
    return local_findings


class PromptsInjectionModule(ScanModule):
    owasp_id = "EXT12"
    category = "Prompt Template Injection"
    name = "prompts-injection"
    description = (
        "Detects prompt injection via MCP prompts/get: static pattern analysis "
        "and dynamic template injection via argument values."
    )
    is_static = False

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Probe 0 — static analysis of known prompts
        for prompt in surface.prompts:
            findings.extend(_check_static_prompt(prompt))

        # Probe 1 — enumerate prompts dynamically
        discovered_prompts: list[dict[str, Any]] = []
        try:
            result = await asyncio.wait_for(
                transport.send_request("prompts/list"),
                timeout=_PROMPTS_TIMEOUT,
            )
            if result and isinstance(result.get("prompts"), list):
                discovered_prompts = result["prompts"]
        except Exception:
            return findings  # prompts/list not supported → skip dynamic probes

        # Probe 2 — template injection via arguments (max 3 prompts)
        for prompt_data in discovered_prompts[:_MAX_PROMPTS_TO_PROBE]:
            pname = prompt_data.get("name", "")
            pargs = prompt_data.get("arguments", [])
            if not pargs:
                continue
            inject_args = {arg["name"]: _INJECT_PAYLOAD for arg in pargs[:2]}
            try:
                get_result = await asyncio.wait_for(
                    transport.send_request("prompts/get", {"name": pname, "arguments": inject_args}),
                    timeout=_PROMPTS_TIMEOUT,
                )
                if get_result is None:
                    continue
                raw = json.dumps(get_result)
                # Check if payload is reflected in messages
                messages = get_result.get("messages", [])
                reflected = any(
                    _INJECT_PAYLOAD in json.dumps(msg) for msg in messages
                )
                if reflected:
                    findings.append(Finding(
                        owasp_category=OWASPCategory.EXT12_PROMPT_INJECTION,
                        severity=Severity.HIGH,
                        title=f"Prompt template injection confirmed in '{pname}'",
                        description=(
                            f"prompts/get for '{pname}' reflected the injection payload "
                            f"verbatim in the returned messages, confirming unsanitized argument "
                            "reflection."
                        ),
                        tool_name=pname,
                        payload=_INJECT_PAYLOAD,
                        evidence=f"Payload reflected in messages: {raw[:300]}",
                        exploitation_confirmed=True,
                        confidence=88,
                        remediation="Sanitize prompt arguments before embedding them in message templates.",
                    ))
                else:
                    findings.append(Finding(
                        owasp_category=OWASPCategory.EXT12_PROMPT_INJECTION,
                        severity=Severity.INFO,
                        title=f"prompts/get endpoint functional for '{pname}'",
                        description="The prompts/get endpoint responded but did not reflect the injection payload.",
                        tool_name=pname,
                        confidence=70,
                        remediation="Verify that prompts/get does not reflect user input without sanitization.",
                    ))
            except Exception:
                continue

        # Probe 3 — info leak via unknown prompt name
        try:
            err_result = await asyncio.wait_for(
                transport.send_request("prompts/get", {"name": "__nonexistent_prompt_corvus__"}),
                timeout=_PROMPTS_TIMEOUT,
            )
            if err_result is not None:
                raw_err = json.dumps(err_result)
                if _STACK_TRACE_RE.search(raw_err):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.EXT12_PROMPT_INJECTION,
                        severity=Severity.MEDIUM,
                        title="Server leaks internal information in prompts/get error response",
                        description=(
                            "prompts/get for a non-existent prompt returned a response containing "
                            "stack trace or internal path information."
                        ),
                        evidence=raw_err[:300],
                        confidence=70,
                        remediation="Return a generic 'prompt not found' error without internal details.",
                    ))
        except Exception:
            pass  # Error on unknown prompt = correct behavior

        return findings

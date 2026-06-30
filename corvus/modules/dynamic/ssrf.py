from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...payloads.engine import PayloadEngine
from ...transport.base import MCPTransport

# Param names that commonly accept URLs or network destinations
_URL_PARAM = re.compile(r"\b(url|host|endpoint|target|uri|src|href|link|address|location)\b", re.I)

# D4: tool description signals URL handling — broadens param candidate set to ALL string params
# No trailing \b — catches conjugations: fetches, navigates, scrapes, downloads, etc.
_URL_DESC = re.compile(
    r"\b(url|navigate|browse|fetch|request|scrape|crawl|webhook|http|download|visit)",
    re.I,
)

# SSRF payloads to probe
_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://localhost/",
]

# Content in the response that confirms the server made the request
_METADATA_SIGNATURES = [
    "ami-id", "instance-id", "instance-type", "meta-data",
    "availability-zone", "iam/security-credentials",
    "computeMetadata", "metadata.google.internal",
]

# Threshold: elapsed > baseline * this factor → likely hanging on a network request
_TIMEOUT_FACTOR = 3.0
# Minimum absolute elapsed (seconds) to consider a timeout signal
_MIN_TIMEOUT_SIGNAL = 3.0


class SSRFModule(ScanModule):
    owasp_id = "EXT04"
    category = "Server-Side Request Forgery"
    name = "ssrf"
    description = (
        "Tests URL/host parameters for SSRF by probing internal metadata endpoints "
        "and measuring response timing anomalies"
    )
    is_static = False

    def __init__(self) -> None:
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

            # D4: if the tool description implies URL handling, treat all string params as
            # URL candidates — catches tools like navigate(url) where param is named generically
            desc_suggests_url = bool(tool.description and _URL_DESC.search(tool.description))
            url_params = [
                (param, pschema)
                for param, pschema in properties.items()
                if pschema.get("type", "string") == "string"
                and (_URL_PARAM.search(param) or desc_suggests_url)
            ]
            if not url_params:
                continue

            # Establish baseline timing with a benign call
            baseline_elapsed = await _benign_elapsed(transport, tool.name, properties, required, self.engine)

            for param, _ in url_params:
                for payload in _SSRF_PAYLOADS:
                    args = self.engine.build_args(properties, required, param, payload)
                    t0 = time.monotonic()
                    try:
                        result = await asyncio.wait_for(
                            transport.send_request("tools/call", {"name": tool.name, "arguments": args}),
                            timeout=12.0,
                        )
                        elapsed = time.monotonic() - t0
                        text = _extract_text(result)

                        # Content signal — server returned metadata content
                        # Exclude signatures that are contained in the payload itself (URL reflection FP)
                        real_sigs = [sig for sig in _METADATA_SIGNATURES if sig in text and sig not in payload]
                        if real_sigs:
                            findings.append(Finding(
                                owasp_category=OWASPCategory.EXT04_SSRF,
                                severity=Severity.CRITICAL,
                                title=f"SSRF — '{tool.name}.{param}' fetched internal metadata",
                                description=(
                                    f"Response to SSRF payload '{payload}' contains cloud metadata "
                                    f"content, confirming the server made a real outbound request."
                                ),
                                tool_name=tool.name,
                                parameter=param,
                                payload=payload,
                                evidence=text[:400],
                                exploitation_confirmed=True,
                                confidence=90,
                                remediation=(
                                    "Block outbound requests to RFC-1918 and link-local ranges. "
                                    "Use an allowlist for permitted URL schemes and hosts."
                                ),
                            ))
                            break  # one finding per param

                        # Timing signal — significant delay vs baseline
                        if elapsed >= _MIN_TIMEOUT_SIGNAL and (
                            baseline_elapsed is None or elapsed > baseline_elapsed * _TIMEOUT_FACTOR
                        ):
                            findings.append(Finding(
                                owasp_category=OWASPCategory.EXT04_SSRF,
                                severity=Severity.HIGH,
                                title=f"SSRF (timing) — '{tool.name}.{param}' delayed on SSRF payload",
                                description=(
                                    f"Call with payload '{payload}' took {elapsed:.1f}s "
                                    + (f"vs baseline {baseline_elapsed:.1f}s" if baseline_elapsed else "(no baseline)")
                                    + " — server likely attempted the outbound request before timing out."
                                ),
                                tool_name=tool.name,
                                parameter=param,
                                payload=payload,
                                confidence=70,
                                remediation=(
                                    "Block outbound requests to RFC-1918 and link-local ranges. "
                                    "Use an allowlist for permitted URL schemes and hosts."
                                ),
                            ))
                            break

                    except asyncio.TimeoutError:
                        elapsed = time.monotonic() - t0
                        findings.append(Finding(
                            owasp_category=OWASPCategory.EXT04_SSRF,
                            severity=Severity.HIGH,
                            title=f"SSRF (timeout) — '{tool.name}.{param}' hung on SSRF payload",
                            description=(
                                f"Call with SSRF payload '{payload}' timed out after {elapsed:.1f}s, "
                                "suggesting the server is attempting the network request."
                            ),
                            tool_name=tool.name,
                            parameter=param,
                            payload=payload,
                            confidence=65,
                            remediation=(
                                "Block outbound requests to RFC-1918 and link-local ranges. "
                                "Use an allowlist for permitted URL schemes and hosts."
                            ),
                        ))
                        break
                    except Exception:
                        pass

        return findings


async def _benign_elapsed(
    transport: MCPTransport,
    tool_name: str,
    properties: dict[str, Any],
    required: list[str],
    engine: PayloadEngine,
) -> float | None:
    benign_args = {
        p: engine.benign_default(s.get("type", "string"))
        for p, s in properties.items()
        if p in required
    }
    t0 = time.monotonic()
    try:
        await transport.send_request("tools/call", {"name": tool_name, "arguments": benign_args})
        return time.monotonic() - t0
    except Exception:
        return None


def _extract_text(result: Any) -> str:
    if not result:
        return ""
    content = result.get("content", []) if isinstance(result, dict) else []
    return " ".join(c.get("text", "") for c in content if isinstance(c, dict))

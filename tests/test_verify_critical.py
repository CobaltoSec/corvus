"""Tests for verify_critical_findings() and module-level _verify_critical() methods."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from corvus.cli import verify_critical_findings
from corvus.core.models import Finding, OWASPCategory, Severity
from corvus.modules.dynamic.cmd_injection import CmdInjectionModule
from corvus.modules.static.auth_audit import AuthAuditModule
from corvus.modules.static.resource_uri import ResourceUriModule
from corvus.transport.base import MCPTransport


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(severity: Severity, confidence: int = 80) -> Finding:
    return Finding(
        owasp_category=OWASPCategory.MCP05_CMD_INJECTION,
        severity=severity,
        title="Test finding",
        description="Test description",
        confidence=confidence,
    )


def _fake_transport(*responses) -> AsyncMock:
    """Return an AsyncMock transport whose send_request returns the given responses in order."""
    transport = AsyncMock(spec=MCPTransport)
    transport.send_request.side_effect = list(responses)
    return transport


# ---------------------------------------------------------------------------
# verify_critical_findings (CLI helper) — existing tests preserved
# ---------------------------------------------------------------------------

def test_empty_findings_returns_zeros():
    verified, total, updated = verify_critical_findings([])
    assert verified == 0
    assert total == 0
    assert updated == []


def test_no_criticals_returns_zero_counts_and_original_list():
    findings = [_finding(Severity.HIGH), _finding(Severity.MEDIUM)]
    verified, total, updated = verify_critical_findings(findings)
    assert verified == 0
    assert total == 0
    assert updated is findings  # same object, unchanged


def test_single_critical_verified():
    findings = [_finding(Severity.CRITICAL)]
    verified, total, updated = verify_critical_findings(findings)
    assert total == 1
    assert verified == 1
    assert len(updated) == 1


def test_multiple_criticals_all_verified():
    findings = [
        _finding(Severity.CRITICAL),
        _finding(Severity.CRITICAL),
        _finding(Severity.HIGH),
    ]
    verified, total, updated = verify_critical_findings(findings)
    assert total == 2
    assert verified == 2
    assert len(updated) == 3  # all findings preserved


def test_non_critical_findings_preserved_in_output():
    findings = [
        _finding(Severity.CRITICAL),
        _finding(Severity.HIGH),
        _finding(Severity.MEDIUM),
        _finding(Severity.LOW),
    ]
    _, _, updated = verify_critical_findings(findings)
    assert len(updated) == 4
    severity_values = {f.severity for f in updated}
    assert Severity.HIGH in severity_values
    assert Severity.MEDIUM in severity_values
    assert Severity.LOW in severity_values
    assert Severity.CRITICAL in severity_values


# ---------------------------------------------------------------------------
# CmdInjectionModule._verify_critical — timing-based FP mitigation
# ---------------------------------------------------------------------------

async def test_cmd_injection_verify_critical_rejects_slow_baseline():
    """Both requests slow but delta < 300ms and same output → timing inconclusive → False."""
    module = CmdInjectionModule()
    transport = _fake_transport(
        {"content": [{"type": "text", "text": "ok"}]},  # baseline response
        {"content": [{"type": "text", "text": "ok"}]},  # inject response (same text)
    )
    props = {"q": {"type": "string"}}

    with patch("corvus.modules.dynamic.cmd_injection.time") as mock_time:
        # baseline: elapsed = 0.8 - 0.0 = 0.8s
        # inject:   elapsed = 1.9 - 1.0 = 0.9s
        # delta = 0.9 - 0.8 = 0.1 < 0.3 → timing fails; text is same → False
        mock_time.monotonic.side_effect = [0.0, 0.8, 1.0, 1.9]
        result = await module._verify_critical(
            transport, "tool", props, [], "q", "'; DROP TABLE users--"
        )

    assert result is False


async def test_cmd_injection_verify_critical_accepts_timing_diff():
    """Inject elapsed - baseline elapsed > 300ms → timing confirms exploitation → True."""
    module = CmdInjectionModule()
    transport = _fake_transport(
        {"content": [{"type": "text", "text": "ok"}]},
        {"content": [{"type": "text", "text": "ok"}]},
    )
    props = {"q": {"type": "string"}}

    with patch("corvus.modules.dynamic.cmd_injection.time") as mock_time:
        # baseline: elapsed = 0.05 - 0.0 = 0.05s
        # inject:   elapsed = 1.5 - 1.0 = 0.5s
        # delta = 0.5 - 0.05 = 0.45 > 0.3 → True
        mock_time.monotonic.side_effect = [0.0, 0.05, 1.0, 1.5]
        result = await module._verify_critical(
            transport, "tool", props, [], "q", "1; SLEEP(5)--"
        )

    assert result is True


# ---------------------------------------------------------------------------
# AuthAuditModule._verify_critical — single-probe auth-bypass check
# ---------------------------------------------------------------------------

async def test_auth_audit_verify_critical_rejects_single_success():
    """Tool call returns isError=True → auth bypass NOT confirmed → False."""
    module = AuthAuditModule()
    transport = _fake_transport(
        {"isError": True, "content": [{"type": "text", "text": "Unauthorized"}]},
    )
    result = await module._verify_critical(transport, "admin_reset")
    assert result is False


async def test_auth_audit_verify_critical_accepts_double_success():
    """Tool call succeeds (no isError, content present) → auth bypass confirmed → True."""
    module = AuthAuditModule()
    transport = _fake_transport(
        {"content": [{"type": "text", "text": "Admin access granted"}]},
    )
    result = await module._verify_critical(transport, "admin_reset")
    assert result is True


# ---------------------------------------------------------------------------
# ResourceUriModule._verify_critical — body + MIME double-gate
# ---------------------------------------------------------------------------

async def test_resource_uri_verify_critical_rejects_partial_match():
    """Sensitive body content found BUT MIME is text/html (doc type) → gate fails → False."""
    module = ResourceUriModule()
    transport = _fake_transport(
        {
            "contents": [{
                "text": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1",
                "mimeType": "text/html",  # doc MIME → content_type_ok=False
            }],
        },
    )
    result = await module._verify_critical(transport, "file:///etc/passwd")
    assert result is False


async def test_resource_uri_verify_critical_accepts_full_match():
    """Sensitive body content AND non-doc MIME → both conditions met → True."""
    module = ResourceUriModule()
    transport = _fake_transport(
        {
            "contents": [{
                "text": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1",
                "mimeType": "text/plain",  # not a doc type → content_type_ok=True
            }],
        },
    )
    result = await module._verify_critical(transport, "file:///etc/passwd")
    assert result is True

"""Tests for CVSS v3.1 vector auto-population on Finding (Item 2 — RT-CORVUS-V30)."""
from __future__ import annotations

import pytest

from corvus.core.models import Finding, OWASPCategory, Severity


def _finding(cat: OWASPCategory, **kwargs) -> Finding:
    return Finding(
        owasp_category=cat,
        severity=Severity.INFO,
        title="t",
        description="d",
        **kwargs,
    )


def test_cvss_auto_populated():
    f = _finding(OWASPCategory.MCP05_CMD_INJECTION)
    assert f.cvss_vector is not None
    assert f.cvss_vector.startswith("AV:")


def test_cvss_all_categories_covered():
    """Every OWASPCategory must have a CVSS vector defined."""
    for cat in OWASPCategory:
        f = _finding(cat)
        assert f.cvss_vector is not None, f"No CVSS vector for {cat}"
        assert f.cvss_vector.startswith("AV:"), f"Malformed CVSS for {cat}: {f.cvss_vector}"


def test_cvss_explicit_override():
    custom = "AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"
    f = _finding(OWASPCategory.MCP05_CMD_INJECTION, cvss_vector=custom)
    assert f.cvss_vector == custom


def test_cvss_cmd_injection_is_critical_vector():
    f = _finding(OWASPCategory.MCP05_CMD_INJECTION)
    # AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H — full network, no auth, scope changed, full CIA
    assert "AV:N" in f.cvss_vector
    assert "PR:N" in f.cvss_vector
    assert "C:H" in f.cvss_vector


def test_cvss_ssrf_vector():
    f = _finding(OWASPCategory.EXT04_SSRF)
    assert f.cvss_vector is not None
    assert "AV:N" in f.cvss_vector
    assert "S:C" in f.cvss_vector  # scope changed — internal network pivot


def test_cvss_log_audit_low_impact():
    f = _finding(OWASPCategory.MCP08_LOG_AUDIT)
    assert f.cvss_vector is not None
    # Lack of audit is low impact — not exploitable directly
    assert "C:L" in f.cvss_vector or "C:N" in f.cvss_vector


def test_cvss_persisted_in_json():
    """cvss_vector must survive JSON serialization round-trip."""
    f = _finding(OWASPCategory.EXT04_SSRF)
    data = f.model_dump()
    assert "cvss_vector" in data
    assert data["cvss_vector"] is not None
    f2 = Finding.model_validate(data)
    assert f2.cvss_vector == f.cvss_vector

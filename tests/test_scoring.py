"""Tests for corvus.scoring."""
from __future__ import annotations

import pytest

from corvus.core.models import Finding, OWASPCategory, ScanResult, MCPSurface, Severity
from corvus.scoring import compute_risk_score, risk_tier, score_result


def _finding(severity: Severity, confidence: int = 100) -> Finding:
    return Finding(
        owasp_category=OWASPCategory.MCP07_AUTH_AUDIT,
        severity=severity,
        title="Test finding",
        description="Test",
        confidence=confidence,
    )


def _result(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        target="http://localhost/mcp",
        transport="http",
        surface=MCPSurface(),
        findings=findings,
    )


# ── compute_risk_score ────────────────────────────────────────────────────────

def test_empty_findings_score_zero():
    assert compute_risk_score([]) == 0


def test_single_critical_full_confidence():
    assert compute_risk_score([_finding(Severity.CRITICAL, 100)]) == 40


def test_single_critical_half_confidence():
    assert compute_risk_score([_finding(Severity.CRITICAL, 50)]) == 20


def test_single_high_full_confidence():
    assert compute_risk_score([_finding(Severity.HIGH, 100)]) == 15


def test_single_medium_full_confidence():
    assert compute_risk_score([_finding(Severity.MEDIUM, 100)]) == 5


def test_single_low_full_confidence():
    assert compute_risk_score([_finding(Severity.LOW, 100)]) == 1


def test_info_contributes_zero():
    assert compute_risk_score([_finding(Severity.INFO, 100)]) == 0


def test_two_criticals_adds_up():
    findings = [_finding(Severity.CRITICAL, 100), _finding(Severity.CRITICAL, 100)]
    assert compute_risk_score(findings) == 80


def test_three_criticals_caps_at_100():
    findings = [_finding(Severity.CRITICAL, 100)] * 3
    assert compute_risk_score(findings) == 100


def test_cap_at_100_regardless_of_count():
    findings = [_finding(Severity.CRITICAL, 100)] * 10
    assert compute_risk_score(findings) == 100


def test_mixed_severities():
    findings = [
        _finding(Severity.HIGH, 100),     # 15
        _finding(Severity.MEDIUM, 100),   # 5
        _finding(Severity.LOW, 100),      # 1
    ]
    assert compute_risk_score(findings) == 21


def test_confidence_zero_contributes_nothing():
    assert compute_risk_score([_finding(Severity.CRITICAL, 0)]) == 0


def test_confidence_scales_linearly():
    score_100 = compute_risk_score([_finding(Severity.CRITICAL, 100)])  # 40
    score_50 = compute_risk_score([_finding(Severity.CRITICAL, 50)])    # 20
    assert score_50 == score_100 // 2  # 20 == 40 // 2


def test_rounding():
    # HIGH at 53 confidence: 15 * 0.53 = 7.95 → rounds to 8
    assert compute_risk_score([_finding(Severity.HIGH, 53)]) == 8


# ── score_result ──────────────────────────────────────────────────────────────

def test_score_result_delegates_to_findings():
    findings = [_finding(Severity.HIGH, 100)]
    result = _result(findings)
    assert score_result(result) == compute_risk_score(findings)


def test_score_result_empty():
    assert score_result(_result([])) == 0


# ── risk_tier ─────────────────────────────────────────────────────────────────

def test_risk_tier_clear():
    assert risk_tier(0) == "CLEAR"


def test_risk_tier_low():
    assert risk_tier(1) == "LOW"
    assert risk_tier(24) == "LOW"


def test_risk_tier_medium():
    assert risk_tier(25) == "MEDIUM"
    assert risk_tier(49) == "MEDIUM"


def test_risk_tier_high():
    assert risk_tier(50) == "HIGH"
    assert risk_tier(74) == "HIGH"


def test_risk_tier_critical():
    assert risk_tier(75) == "CRITICAL"
    assert risk_tier(100) == "CRITICAL"


def test_risk_tier_boundary_75():
    assert risk_tier(74) == "HIGH"
    assert risk_tier(75) == "CRITICAL"


def test_risk_tier_boundary_50():
    assert risk_tier(49) == "MEDIUM"
    assert risk_tier(50) == "HIGH"


def test_risk_tier_boundary_25():
    assert risk_tier(24) == "LOW"
    assert risk_tier(25) == "MEDIUM"

"""Tests for verify_critical_findings()."""
from __future__ import annotations

from corvus.cli import verify_critical_findings
from corvus.core.models import Finding, OWASPCategory, Severity


def _finding(severity: Severity, confidence: int = 80) -> Finding:
    return Finding(
        owasp_category=OWASPCategory.MCP05_CMD_INJECTION,
        severity=severity,
        title="Test finding",
        description="Test description",
        confidence=confidence,
    )


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

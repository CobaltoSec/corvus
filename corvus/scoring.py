"""scoring.py — Risk Score computation for MCP scan results."""
from __future__ import annotations

from .core.models import Finding, ScanResult, Severity

_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH:     15,
    Severity.MEDIUM:    5,
    Severity.LOW:       1,
    Severity.INFO:      0,
}


def compute_risk_score(findings: list[Finding]) -> int:
    """Compute a Risk Score 0–100 from a list of findings.

    Each finding contributes weight × (confidence / 100).
    Weights: CRITICAL=40, HIGH=15, MEDIUM=5, LOW=1, INFO=0.
    Score is capped at 100.
    """
    if not findings:
        return 0
    total = sum(
        _SEVERITY_WEIGHTS[f.severity] * (f.confidence / 100)
        for f in findings
    )
    return min(100, round(total))


def score_result(result: ScanResult) -> int:
    """Compute Risk Score from a ScanResult."""
    return compute_risk_score(result.findings)


def risk_tier(score: int) -> str:
    """Return a risk tier label for a given score.

    CRITICAL ≥75, HIGH ≥50, MEDIUM ≥25, LOW >0, CLEAR =0.
    """
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "CLEAR"

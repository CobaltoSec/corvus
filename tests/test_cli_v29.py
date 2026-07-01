"""Tests for RT-CORVUS-V29: init, report, --score, --delay, --env, HTML output."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from corvus.cli import app
from corvus.config import CorvusConfig, ScanConfig
from corvus.core.models import Finding, MCPSurface, OWASPCategory, ScanResult, Severity
from corvus.reporting.report import ReportGenerator

runner = CliRunner()

# ── Helpers ──────────────────────────────────────────────────────────────────


def _finding(sev: Severity = Severity.HIGH, confidence: int = 80) -> Finding:
    return Finding(
        owasp_category=OWASPCategory.MCP07_AUTH_AUDIT,
        severity=sev,
        title="Test finding",
        description="A test vulnerability",
        remediation="Fix it",
        confidence=confidence,
    )


def _scan_result(findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        target="test://mock",
        transport="stdio",
        surface=MCPSurface(),
        findings=[_finding()] if findings is None else findings,
        modules_run=["tool-poisoning"],
    )


def _write_report_json(tmp_path: Path, result: ScanResult | None = None) -> Path:
    result = result or _scan_result()
    p = tmp_path / "report.json"
    p.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return p


# ── corvus init ───────────────────────────────────────────────────────────────


def test_init_creates_toml(tmp_path: Path) -> None:
    dest = tmp_path / "corvus.toml"
    result = runner.invoke(app, ["init", "--output", str(dest)])
    assert result.exit_code == 0, result.output
    assert dest.exists()
    content = dest.read_text()
    assert "[scan]" in content
    assert "transport" in content
    assert "timeout" in content
    assert "delay" in content


def test_init_default_filename(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "corvus.toml").exists()


def test_init_refuses_to_overwrite(tmp_path: Path) -> None:
    dest = tmp_path / "corvus.toml"
    dest.write_text("[scan]\n")
    result = runner.invoke(app, ["init", "--output", str(dest)])
    assert result.exit_code != 0
    assert "already exists" in result.output


def test_init_skeleton_is_valid_toml(tmp_path: Path) -> None:
    import tomllib
    dest = tmp_path / "corvus.toml"
    runner.invoke(app, ["init", "--output", str(dest)])
    with open(dest, "rb") as fh:
        parsed = tomllib.load(fh)
    assert "scan" in parsed


# ── corvus report ─────────────────────────────────────────────────────────────


def test_report_generates_md(tmp_path: Path) -> None:
    rj = _write_report_json(tmp_path)
    result = runner.invoke(app, ["report", str(rj), "--format", "md"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "report.md").exists()


def test_report_generates_sarif(tmp_path: Path) -> None:
    rj = _write_report_json(tmp_path)
    result = runner.invoke(app, ["report", str(rj), "--format", "sarif"])
    assert result.exit_code == 0, result.output
    sarif = tmp_path / "report.sarif"
    assert sarif.exists()
    data = json.loads(sarif.read_text())
    assert data["version"] == "2.1.0"


def test_report_generates_html(tmp_path: Path) -> None:
    rj = _write_report_json(tmp_path)
    result = runner.invoke(app, ["report", str(rj), "--format", "html"])
    assert result.exit_code == 0, result.output
    html = tmp_path / "report.html"
    assert html.exists()
    content = html.read_text()
    assert "<!DOCTYPE html>" in content
    assert "Test finding" in content
    assert "Risk Score" in content


def test_report_all_formats(tmp_path: Path) -> None:
    rj = _write_report_json(tmp_path)
    result = runner.invoke(app, ["report", str(rj), "--format", "all"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.sarif").exists()
    assert (tmp_path / "report.html").exists()


def test_report_missing_file(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", str(tmp_path / "nope.json")])
    assert result.exit_code != 0
    assert "not found" in result.output.lower()


def test_report_invalid_json(tmp_path: Path) -> None:
    bad = tmp_path / "report.json"
    bad.write_text("not json", encoding="utf-8")
    result = runner.invoke(app, ["report", str(bad)])
    assert result.exit_code != 0


def test_report_unknown_format(tmp_path: Path) -> None:
    rj = _write_report_json(tmp_path)
    result = runner.invoke(app, ["report", str(rj), "--format", "pdf"])
    assert result.exit_code != 0
    assert "Unknown format" in result.output


def test_report_output_dir(tmp_path: Path) -> None:
    rj = _write_report_json(tmp_path)
    out = tmp_path / "custom-out"
    result = runner.invoke(app, ["report", str(rj), "--format", "html", "--output-dir", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "report.html").exists()


# ── HTML report generation ────────────────────────────────────────────────────


def test_html_report_contains_severity_badge(tmp_path: Path) -> None:
    gen = ReportGenerator(tmp_path)
    result = _scan_result([_finding(Severity.CRITICAL, 95)])
    path = gen.write_html(result)
    content = path.read_text()
    assert "badge-critical" in content
    assert "CRITICAL" in content


def test_html_report_contains_confidence(tmp_path: Path) -> None:
    gen = ReportGenerator(tmp_path)
    result = _scan_result([_finding(Severity.HIGH, 73)])
    path = gen.write_html(result)
    assert "73%" in path.read_text()


def test_html_report_risk_score(tmp_path: Path) -> None:
    gen = ReportGenerator(tmp_path)
    result = _scan_result([_finding(Severity.CRITICAL, 100), _finding(Severity.CRITICAL, 100)])
    path = gen.write_html(result)
    content = path.read_text()
    assert "80/100" in content
    assert "HIGH" in content


def test_html_report_no_findings(tmp_path: Path) -> None:
    gen = ReportGenerator(tmp_path)
    result = _scan_result([])
    path = gen.write_html(result)
    content = path.read_text()
    assert "No findings detected" in content
    assert "0/100" in content


def test_html_report_shows_remediation(tmp_path: Path) -> None:
    gen = ReportGenerator(tmp_path)
    f = Finding(
        owasp_category=OWASPCategory.MCP03_TOOL_POISONING,
        severity=Severity.HIGH,
        title="XYZ",
        description="desc",
        remediation="Apply patch X immediately",
    )
    result = _scan_result([f])
    content = gen.write_html(result).read_text()
    assert "Apply patch X immediately" in content


# ── MD confidence column ──────────────────────────────────────────────────────


def test_md_report_contains_confidence(tmp_path: Path) -> None:
    gen = ReportGenerator(tmp_path)
    result = _scan_result([_finding(Severity.MEDIUM, 60)])
    path = gen.write_md(result)
    assert "60%" in path.read_text()


# ── config: delay + env fields ────────────────────────────────────────────────


def test_config_delay_default() -> None:
    cfg = CorvusConfig()
    assert cfg.scan.delay == 0.0


def test_config_env_default() -> None:
    cfg = CorvusConfig()
    assert cfg.scan.env == {}


def test_config_delay_from_toml(tmp_path: Path) -> None:
    import tomllib
    f = tmp_path / "c.toml"
    f.write_text("[scan]\ndelay = 1.5\n", encoding="utf-8")
    from corvus.config import load_config
    cfg = load_config(f)
    assert cfg.scan.delay == 1.5


def test_config_env_from_toml(tmp_path: Path) -> None:
    f = tmp_path / "c.toml"
    f.write_text('[scan]\n[scan.env]\nMY_KEY = "myval"\n', encoding="utf-8")
    from corvus.config import load_config
    cfg = load_config(f)
    assert cfg.scan.env == {"MY_KEY": "myval"}


def test_config_fixture_has_env() -> None:
    from corvus.config import load_config
    cfg = load_config(Path(__file__).parent / "fixtures" / "sample_config.toml")
    assert cfg.scan.env.get("TEST_VAR") == "hello"


# ── E2E: corvus scan --score against mock server ──────────────────────────────


def test_scan_score_flag_e2e(tmp_path: Path) -> None:
    """corvus scan --score prints risk score line after the summary table."""
    from .conftest import MOCK_SERVER_CMD
    cmd_str = " ".join(MOCK_SERVER_CMD)
    result = runner.invoke(app, [
        "scan",
        "--cmd", cmd_str,
        "--module", "tool-poisoning",
        "--output-dir", str(tmp_path),
        "--score",
    ])
    assert result.exit_code == 0, result.output
    assert "Risk Score" in result.output
    assert "/100" in result.output


def test_scan_confidence_shown_in_output(tmp_path: Path) -> None:
    """Each finding line includes a confidence percentage."""
    from .conftest import MOCK_SERVER_CMD
    cmd_str = " ".join(MOCK_SERVER_CMD)
    result = runner.invoke(app, [
        "scan",
        "--cmd", cmd_str,
        "--module", "tool-poisoning",
        "--output-dir", str(tmp_path),
    ])
    assert result.exit_code == 0, result.output
    assert "%" in result.output

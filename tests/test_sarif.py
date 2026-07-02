"""Tests for SARIF 2.1.0 report output."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from corvus.core.models import Finding, MCPSurface, OWASPCategory, ScanResult, Severity
from corvus.reporting.report import ReportGenerator, write_combined_sarif


def _minimal_result() -> ScanResult:
    surface = MCPSurface(server_name="test-server", tools=[])
    findings = [
        Finding(
            owasp_category=OWASPCategory.MCP03_TOOL_POISONING,
            severity=Severity.CRITICAL,
            title="Poisoned tool detected",
            description="Tool description contains hidden instructions.",
            tool_name="evil_tool",
            remediation="Remove hidden instructions.",
        ),
        Finding(
            owasp_category=OWASPCategory.MCP01_TOKEN_EXPOSURE,
            severity=Severity.HIGH,
            title="Credential leaked",
            description="Response contains API key.",
            tool_name="server_status",
        ),
        Finding(
            owasp_category=OWASPCategory.EXT02_SCHEMA_AUDIT,
            severity=Severity.MEDIUM,
            title="Weak schema",
            description="Parameter accepts any type.",
            tool_name="run_cmd",
        ),
    ]
    return ScanResult(
        target="test-server",
        transport="stdio",
        surface=surface,
        findings=findings,
        modules_run=["tool-poisoning", "token-exposure", "schema-audit"],
    )


def test_sarif_is_valid_json(tmp_path: Path) -> None:
    gen = ReportGenerator(tmp_path)
    sarif_path = gen.write_sarif(_minimal_result())
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert "runs" in data
    assert len(data["runs"]) == 1


def test_sarif_tool_driver(tmp_path: Path) -> None:
    gen = ReportGenerator(tmp_path)
    sarif_path = gen.write_sarif(_minimal_result())
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "corvus"
    assert "version" in driver
    assert "rules" in driver


def test_sarif_rules_deduplicated(tmp_path: Path) -> None:
    gen = ReportGenerator(tmp_path)
    sarif_path = gen.write_sarif(_minimal_result())
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    # One rule per OWASP category; no duplicates
    assert len(rule_ids) == len(set(rule_ids))
    assert "CORVUS-MCP03" in rule_ids   # tool-poisoning
    assert "CORVUS-MCP01" in rule_ids   # token-exposure
    assert "CORVUS-EXT02" in rule_ids   # schema-audit


def test_sarif_results_count(tmp_path: Path) -> None:
    gen = ReportGenerator(tmp_path)
    sarif_path = gen.write_sarif(_minimal_result())
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    results = data["runs"][0]["results"]
    assert len(results) == 3


def test_sarif_severity_mapping(tmp_path: Path) -> None:
    gen = ReportGenerator(tmp_path)
    sarif_path = gen.write_sarif(_minimal_result())
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    results = data["runs"][0]["results"]

    by_rule = {r["ruleId"]: r["level"] for r in results}
    assert by_rule["CORVUS-MCP03"] == "error"    # CRITICAL (tool-poisoning)
    assert by_rule["CORVUS-MCP01"] == "error"    # HIGH (token-exposure)
    assert by_rule["CORVUS-EXT02"] == "warning"  # MEDIUM (schema-audit)


def test_sarif_location_has_tool_name(tmp_path: Path) -> None:
    gen = ReportGenerator(tmp_path)
    sarif_path = gen.write_sarif(_minimal_result())
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    results = data["runs"][0]["results"]

    evil_result = next(r for r in results if r["ruleId"] == "CORVUS-MCP03")
    locs = evil_result.get("locations", [])
    assert locs, "Expected at least one location for a finding with tool_name"
    logical = locs[0]["logicalLocations"][0]
    assert logical["name"] == "evil_tool"
    assert logical["kind"] == "function"


def test_sarif_invocations(tmp_path: Path) -> None:
    gen = ReportGenerator(tmp_path)
    sarif_path = gen.write_sarif(_minimal_result())
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    invocations = data["runs"][0].get("invocations", [])
    assert invocations
    assert invocations[0]["executionSuccessful"] is True


def test_write_combined_sarif_multiple_targets(tmp_path: Path) -> None:
    r1 = _minimal_result()
    r2 = ScanResult(
        target="server-b",
        transport="http",
        surface=MCPSurface(server_name="server-b"),
        findings=[
            Finding(
                owasp_category=OWASPCategory.EXT04_SSRF,
                severity=Severity.HIGH,
                title="SSRF found",
                description="SSRF in resource fetch.",
                remediation="Validate URLs.",
            )
        ],
        modules_run=["ssrf"],
    )

    path = write_combined_sarif([("server-a", r1), ("server-b", r2)], tmp_path)
    assert path.name == "combined.sarif"

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 2


def test_write_combined_sarif_tags_targets(tmp_path: Path) -> None:
    r1 = _minimal_result()
    r2 = ScanResult(
        target="another-server",
        transport="stdio",
        surface=MCPSurface(),
        findings=[],
        modules_run=[],
    )

    path = write_combined_sarif([("alpha", r1), ("beta", r2)], tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    ids = {run.get("automationDetails", {}).get("id") for run in data["runs"]}
    assert "alpha" in ids
    assert "beta" in ids


def test_write_combined_sarif_single_target(tmp_path: Path) -> None:
    path = write_combined_sarif([("only", _minimal_result())], tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert len(data["runs"]) == 1

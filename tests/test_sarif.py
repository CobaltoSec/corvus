"""Tests for SARIF 2.1.0 report output."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from corvus.core.models import Finding, MCPSurface, OWASPCategory, ScanResult, Severity
from corvus.reporting.report import ReportGenerator


def _minimal_result() -> ScanResult:
    surface = MCPSurface(server_name="test-server", tools=[])
    findings = [
        Finding(
            owasp_category=OWASPCategory.MCP01_TOOL_POISONING,
            severity=Severity.CRITICAL,
            title="Poisoned tool detected",
            description="Tool description contains hidden instructions.",
            tool_name="evil_tool",
            remediation="Remove hidden instructions.",
        ),
        Finding(
            owasp_category=OWASPCategory.MCP04_INFO_DISCLOSURE,
            severity=Severity.HIGH,
            title="Credential leaked",
            description="Response contains API key.",
            tool_name="server_status",
        ),
        Finding(
            owasp_category=OWASPCategory.MCP09_SCHEMA_AUDIT,
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
        modules_run=["tool-poisoning", "info-disclosure", "schema-audit"],
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
    assert "CORVUS-MCP01" in rule_ids
    assert "CORVUS-MCP04" in rule_ids
    assert "CORVUS-MCP09" in rule_ids


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
    assert by_rule["CORVUS-MCP01"] == "error"    # CRITICAL → error
    assert by_rule["CORVUS-MCP04"] == "error"    # HIGH → error
    assert by_rule["CORVUS-MCP09"] == "warning"  # MEDIUM → warning


def test_sarif_location_has_tool_name(tmp_path: Path) -> None:
    gen = ReportGenerator(tmp_path)
    sarif_path = gen.write_sarif(_minimal_result())
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    results = data["runs"][0]["results"]

    evil_result = next(r for r in results if r["ruleId"] == "CORVUS-MCP01")
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

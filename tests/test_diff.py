"""Tests for corvus.diff."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from corvus.diff import DiffResult, _result_key, _severity_from_level, diff_sarifs, load_sarif_results


def _make_sarif(results: list[dict]) -> dict:
    return {
        "version": "2.1.0",
        "$schema": "...",
        "runs": [{"tool": {"driver": {"name": "corvus"}}, "results": results}],
    }


def _result(rule_id: str, message: str, level: str = "error") -> dict:
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
    }


def _write_sarif(path: Path, results: list[dict]) -> None:
    path.write_text(json.dumps(_make_sarif(results)), encoding="utf-8")


# ── load_sarif_results ────────────────────────────────────────────────────────

def test_load_empty_sarif(tmp_path):
    p = tmp_path / "empty.sarif"
    _write_sarif(p, [])
    assert load_sarif_results(p) == []


def test_load_single_result(tmp_path):
    r = _result("MCP07", "Auth bypass")
    p = tmp_path / "one.sarif"
    _write_sarif(p, [r])
    results = load_sarif_results(p)
    assert len(results) == 1
    assert results[0]["ruleId"] == "MCP07"


def test_load_multiple_results(tmp_path):
    p = tmp_path / "multi.sarif"
    _write_sarif(p, [_result("MCP07", "A"), _result("MCP01", "B"), _result("EXT01", "C")])
    assert len(load_sarif_results(p)) == 3


def test_load_multiple_runs(tmp_path):
    data = {
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": "corvus"}}, "results": [_result("R1", "a"), _result("R2", "b")]},
            {"tool": {"driver": {"name": "corvus"}}, "results": [_result("R3", "c"), _result("R4", "d")]},
        ],
    }
    p = tmp_path / "two_runs.sarif"
    p.write_text(json.dumps(data), encoding="utf-8")
    assert len(load_sarif_results(p)) == 4


def test_load_missing_runs(tmp_path):
    p = tmp_path / "no_runs.sarif"
    p.write_text(json.dumps({"version": "2.1.0"}), encoding="utf-8")
    assert load_sarif_results(p) == []


# ── _result_key ───────────────────────────────────────────────────────────────

def test_result_key_format():
    r = _result("MCP07", "Auth bypass")
    assert _result_key(r) == "MCP07::Auth bypass"


def test_result_key_truncates_message():
    long_msg = "x" * 200
    r = _result("MCP01", long_msg)
    key = _result_key(r)
    msg_part = key.split("::", 1)[1]
    assert len(msg_part) == 120


def test_result_key_empty_rule_id():
    r = {"message": {"text": "some finding"}}
    assert _result_key(r) == "::some finding"


def test_result_key_stable():
    r = _result("EXT01", "Batch DoS")
    assert _result_key(r) == _result_key(r)


def test_result_key_different_rules_differ():
    r1 = _result("MCP07", "same message")
    r2 = _result("MCP01", "same message")
    assert _result_key(r1) != _result_key(r2)


def test_result_key_different_messages_differ():
    r1 = _result("MCP07", "message A")
    r2 = _result("MCP07", "message B")
    assert _result_key(r1) != _result_key(r2)


# ── _severity_from_level ──────────────────────────────────────────────────────

def test_severity_error():
    assert _severity_from_level("error") == "HIGH"


def test_severity_warning():
    assert _severity_from_level("warning") == "MEDIUM"


def test_severity_note():
    assert _severity_from_level("note") == "LOW"


def test_severity_none():
    assert _severity_from_level("none") == "INFO"


def test_severity_unknown():
    assert _severity_from_level("bogus") == "UNKNOWN"


def test_severity_null():
    assert _severity_from_level(None) == "UNKNOWN"


# ── diff_sarifs ───────────────────────────────────────────────────────────────

def test_diff_identical_sarifs(tmp_path):
    results = [_result("MCP07", "Auth bypass"), _result("EXT01", "Batch DoS")]
    p = tmp_path / "scan.sarif"
    _write_sarif(p, results)
    diff = diff_sarifs(p, p)
    assert diff.new == []
    assert diff.fixed == []
    assert diff.unchanged_count == 2


def test_diff_new_finding(tmp_path):
    old = tmp_path / "old.sarif"
    new = tmp_path / "new.sarif"
    _write_sarif(old, [])
    r = _result("MCP07", "Auth bypass")
    _write_sarif(new, [r])
    diff = diff_sarifs(old, new)
    assert len(diff.new) == 1
    assert diff.fixed == []
    assert diff.unchanged_count == 0


def test_diff_fixed_finding(tmp_path):
    old = tmp_path / "old.sarif"
    new = tmp_path / "new.sarif"
    r = _result("MCP07", "Auth bypass")
    _write_sarif(old, [r])
    _write_sarif(new, [])
    diff = diff_sarifs(old, new)
    assert diff.new == []
    assert len(diff.fixed) == 1
    assert diff.unchanged_count == 0


def test_diff_mixed(tmp_path):
    old = tmp_path / "old.sarif"
    new = tmp_path / "new.sarif"
    r1 = _result("MCP07", "Auth bypass")
    r2 = _result("EXT01", "Batch DoS")
    r3 = _result("MCP01", "Token exposure")
    _write_sarif(old, [r1, r2])
    _write_sarif(new, [r2, r3])
    diff = diff_sarifs(old, new)
    assert len(diff.new) == 1
    assert diff.new[0]["ruleId"] == "MCP01"
    assert len(diff.fixed) == 1
    assert diff.fixed[0]["ruleId"] == "MCP07"
    assert diff.unchanged_count == 1


def test_diff_empty_to_empty(tmp_path):
    old = tmp_path / "old.sarif"
    new = tmp_path / "new.sarif"
    _write_sarif(old, [])
    _write_sarif(new, [])
    diff = diff_sarifs(old, new)
    assert diff.new == []
    assert diff.fixed == []
    assert diff.unchanged_count == 0


def test_diff_result_objects_preserved(tmp_path):
    old = tmp_path / "old.sarif"
    new = tmp_path / "new.sarif"
    _write_sarif(old, [])
    r = _result("MCP07", "Auth bypass", level="error")
    _write_sarif(new, [r])
    diff = diff_sarifs(old, new)
    assert diff.new[0]["ruleId"] == "MCP07"
    assert diff.new[0]["level"] == "error"
    assert diff.new[0]["message"]["text"] == "Auth bypass"

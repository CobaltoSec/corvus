"""diff.py — Compare two Corvus SARIF reports to detect new/fixed findings."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DiffResult:
    new: list[dict] = field(default_factory=list)       # findings in new, not in old
    fixed: list[dict] = field(default_factory=list)     # findings in old, not in new
    unchanged_count: int = 0


def load_sarif_results(path: Path) -> list[dict]:
    """Load all results from a SARIF 2.1.0 file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    results: list[dict] = []
    for run in data.get("runs", []):
        results.extend(run.get("results", []))
    return results


def _result_key(result: dict) -> str:
    """Stable dedup key: ruleId + first 120 chars of message text."""
    rule_id = result.get("ruleId", "")
    msg = result.get("message", {}).get("text", "")[:120]
    return f"{rule_id}::{msg}"


def diff_sarifs(old_path: Path, new_path: Path) -> DiffResult:
    """Compare two SARIF files.  Returns new, fixed, and unchanged counts."""
    old_results = load_sarif_results(old_path)
    new_results = load_sarif_results(new_path)

    old_keys = {_result_key(r): r for r in old_results}
    new_keys = {_result_key(r): r for r in new_results}

    new_findings = [r for k, r in new_keys.items() if k not in old_keys]
    fixed_findings = [r for k, r in old_keys.items() if k not in new_keys]
    unchanged = len(set(old_keys) & set(new_keys))

    return DiffResult(new=new_findings, fixed=fixed_findings, unchanged_count=unchanged)


def _severity_from_level(level: str | None) -> str:
    """Map SARIF level to severity label."""
    return {
        "error": "HIGH",
        "warning": "MEDIUM",
        "note": "LOW",
        "none": "INFO",
    }.get(level or "", "UNKNOWN")

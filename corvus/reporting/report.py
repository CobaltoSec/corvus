from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from .. import __version__ as _VERSION
from ..core.models import Severity, ScanResult

_TEMPLATE_DIR = Path(__file__).parent / "templates"

_SEVERITY_TO_SARIF: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "none",
}


class ReportGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=False)

    def write(self, result: ScanResult) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)

        json_path = self.output_dir / "report.json"
        json_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")

        md_path = self.output_dir / "report.md"
        tpl = self.env.get_template("report.md.j2")
        md_path.write_text(
            tpl.render(result=result, now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            encoding="utf-8",
        )
        return md_path

    def write_sarif(self, result: ScanResult) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        sarif_path = self.output_dir / "report.sarif"
        sarif_path.write_text(
            json.dumps(_build_sarif(result), indent=2),
            encoding="utf-8",
        )
        return sarif_path


def _build_sarif(result: ScanResult) -> dict:
    # Collect unique rules, preserving insertion order (one rule per OWASP category)
    rules_seen: dict[str, dict] = {}
    for f in result.findings:
        rule_id = f"CORVUS-{f.owasp_category.value}"
        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "name": f.owasp_category.value,
                "shortDescription": {"text": f.owasp_category.value},
                "helpUri": "https://github.com/CobaltoSec/corvus",
                "properties": {"tags": ["security", "mcp", "owasp"]},
            }

    sarif_results: list[dict] = []
    for f in result.findings:
        rule_id = f"CORVUS-{f.owasp_category.value}"
        entry: dict = {
            "ruleId": rule_id,
            "level": _SEVERITY_TO_SARIF.get(f.severity, "warning"),
            "message": {"text": f"{f.title}. {f.description}"},
        }
        if f.tool_name:
            entry["locations"] = [
                {"logicalLocations": [{"name": f.tool_name, "kind": "function"}]}
            ]
        sarif_results.append(entry)

    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "corvus",
                        "version": _VERSION,
                        "informationUri": "https://github.com/CobaltoSec/corvus",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": f"corvus scan --transport {result.transport}",
                    }
                ],
            }
        ],
    }

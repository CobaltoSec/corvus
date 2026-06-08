from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ..core.models import ScanResult

_TEMPLATE_DIR = Path(__file__).parent / "templates"


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

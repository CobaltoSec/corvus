"""Post-run batch funnel summary generator."""
from __future__ import annotations

from datetime import date
from pathlib import Path


def generate_batch_summary(
    run_name: str,
    targets_total: int,
    targets_ok: int,
    targets_error: int,
    raw_findings: int,
    severity_counts: dict,
    output_dir: Path = None,
) -> Path:
    """Generate a markdown funnel summary for a completed batch run.

    Parameters
    ----------
    run_name:        Short identifier for the run (e.g. ``targets-v08`` or timestamp).
    targets_total:   Total number of targets in the batch.
    targets_ok:      Targets that completed without error.
    targets_error:   Targets that failed with an error.
    raw_findings:    Total findings across all OK targets.
    severity_counts: Dict mapping severity name → count (e.g. ``{"critical": 3, "high": 7}``).
    output_dir:      Directory to write the file in.  Defaults to ``~/.corvus/summaries/``.

    Returns
    -------
    Path to the generated markdown file.
    """
    if output_dir is None:
        output_dir = Path.home() / ".corvus" / "summaries"
    output_dir.mkdir(parents=True, exist_ok=True)

    today = date.today().isoformat()
    pct_ok = round(targets_ok / targets_total * 100, 1) if targets_total else 0.0
    pct_err = round(targets_error / targets_total * 100, 1) if targets_total else 0.0

    lines = [
        f"## Corvus {run_name} — {today}",
        "",
        "| Etapa | Count | % |",
        "|-------|-------|---|",
        f"| Targets totales | {targets_total} | 100% |",
        f"| Targets OK | {targets_ok} | {pct_ok}% |",
        f"| Targets ERROR | {targets_error} | {pct_err}% |",
        f"| Raw findings | {raw_findings} | — |",
    ]

    _SEV_ORDER = ["critical", "high", "medium", "low"]

    def _sev_key(item: tuple) -> int:
        sev = item[0]
        return _SEV_ORDER.index(sev) if sev in _SEV_ORDER else 99

    for sev, count in sorted(severity_counts.items(), key=_sev_key):
        lines.append(f"| {sev.capitalize()} | {count} | — |")

    content = "\n".join(lines) + "\n"
    out_path = output_dir / f"run-{run_name}-{today}.md"
    out_path.write_text(content, encoding="utf-8")
    return out_path

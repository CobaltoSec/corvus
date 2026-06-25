#!/usr/bin/env python3
"""CS01 — MCP Ecosystem Audit CLI.

Commands:
  status                           Show target state table
  scan [--tier A|B|C] [--name N]  Run corvus batch on pending/error targets
       [--all]                     Include already-done targets too
  update <output-dir>              Update state from existing corvus output dir
  add <name> --tier X [opts]       Add a new target to the master YAML

Examples:
  python cs01.py status
  python cs01.py scan --tier A
  python cs01.py scan --name server-sqlite
  python cs01.py update batch-scans/20260624-120000
  python cs01.py add mcp-my-server --tier B --cmd npx -y mcp-my-server
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import yaml

HERE = Path(__file__).parent
MASTER = HERE / "targets-master.yaml"
BATCH_DIR = HERE / "batch-scans"

# ── Status colors (ANSI) ──────────────────────────────────────────────────────

_STATUS_COLOR = {
    "done":    "\033[32m",  # green
    "partial": "\033[33m",  # yellow
    "pending": "\033[36m",  # cyan
    "error":   "\033[31m",  # red
    "skip":    "\033[90m",  # dark gray
}
_RESET = "\033[0m"
_BOLD  = "\033[1m"


def _col(text: str, color: str) -> str:
    return f"{color}{text}{_RESET}"


# ── YAML I/O ─────────────────────────────────────────────────────────────────

def _load() -> dict:
    with open(MASTER, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _save(data: dict) -> None:
    with open(MASTER, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


# ── Corvus binary detection ───────────────────────────────────────────────────

def _corvus_bin() -> str:
    # Prefer venv's corvus (repo root)
    for candidate in [
        HERE.parent.parent / ".venv" / "Scripts" / "corvus.exe",
        HERE.parent.parent / ".venv" / "Scripts" / "corvus",
        HERE.parent.parent / ".venv" / "bin" / "corvus",
    ]:
        if candidate.exists():
            return str(candidate)
    # Fall back to PATH
    found = shutil.which("corvus")
    if found:
        return found
    print("ERROR: corvus binary not found. Activate the venv or install corvus.")
    sys.exit(1)


# ── State update from output dir ─────────────────────────────────────────────

def _update_from_dir(output_dir: Path, data: dict, target_names: set) -> int:
    target_map = {t["name"]: t for t in data["targets"]}
    updated = 0
    today = datetime.now().strftime("%Y-%m-%d")

    for subdir in sorted(output_dir.iterdir()):
        if not subdir.is_dir():
            continue
        name = subdir.name
        if name not in target_names:
            continue
        t = target_map.get(name)
        if t is None:
            continue

        report_path = subdir / "report.json"
        if not report_path.exists():
            t["status"] = "error"
            t["last_scanned"] = today
            t["findings_summary"] = "ERROR (no report.json)"
            updated += 1
            continue

        with open(report_path, encoding="utf-8") as f:
            report = json.load(f)

        findings = report.get("findings", [])
        counts: dict[str, int] = {}
        for finding in findings:
            sev = finding.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1

        parts = []
        for sev, label in [("critical","C"), ("high","H"), ("medium","M"), ("low","L"), ("info","I")]:
            if counts.get(sev):
                parts.append(f"{counts[sev]}{label}")
        summary = " ".join(parts) if parts else "clean"

        t["status"] = "done"
        t["last_scanned"] = today
        t["findings_summary"] = summary
        if "curation" not in t:
            t["curation"] = "pending"
        updated += 1

    return updated


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_status(_args: argparse.Namespace, data: dict) -> None:
    targets = data["targets"]
    tiers = sorted({t.get("tier", "?") for t in targets})

    total = len(targets)
    done = sum(1 for t in targets if t.get("status") == "done")
    pending = sum(1 for t in targets if t.get("status") in (None, "pending", "error"))

    print(f"\n{_BOLD}CS01 — MCP Ecosystem Audit{_RESET}  "
          f"(corvus {data['meta'].get('corvus_version','?')})")
    print(f"Targets: {total}  Done: {done}  Pending: {pending}\n")

    for tier in tiers:
        tier_targets = [t for t in targets if t.get("tier") == tier]
        print(f"{_BOLD}Tier {tier}{_RESET}")
        fmt = "{:<35} {:<10} {:<18} {:<10} {}"
        print(fmt.format("Name", "Status", "Findings", "Curation", "Notes"))
        print("─" * 100)
        for t in tier_targets:
            status = t.get("status", "pending")
            color = _STATUS_COLOR.get(status, "")
            print(fmt.format(
                t["name"],
                _col(status, color),
                t.get("findings_summary", "—"),
                t.get("curation", "—"),
                (t.get("notes") or "")[:50],
            ))
        print()


def cmd_scan(args: argparse.Namespace, data: dict) -> None:
    RUNNABLE = {"pending", "error", None}
    exclude_set = set(args.exclude) if getattr(args, "exclude", None) else set()

    selected = []
    for t in data["targets"]:
        if args.name and t["name"] != args.name:
            continue
        if args.tier and t.get("tier") != args.tier:
            continue
        if t["name"] in exclude_set:
            print(f"[SKIP] {t['name']}: excluded via --exclude")
            continue
        # --redone: select only already-done targets (excludes skip)
        if getattr(args, "redone", False):
            if t.get("status") != "done":
                continue
        elif not args.all and t.get("status") not in RUNNABLE:
            continue
        # HTTP targets without url need manual startup — skip with warning
        if t.get("transport") == "http":
            if not t.get("url"):
                print(f"[WARN] {t['name']}: HTTP target with no url — skipping")
                continue
            print(f"[INFO] {t['name']}: HTTP target — ensure server is running at {t['url']}")
        selected.append(t)

    if not selected:
        print("No targets to scan (all done, or none match filter).")
        print("Use --all to re-scan already-done targets, --redone to re-scan done ones.")
        return

    print(f"Scanning {len(selected)} target(s): {[t['name'] for t in selected]}\n")

    # Generate temp batch YAML
    batch_targets = []
    for t in selected:
        entry: dict = {"name": t["name"], "transport": t.get("transport", "stdio")}
        if t.get("cmd"):
            entry["cmd"] = t["cmd"]
        if t.get("url"):
            entry["url"] = t["url"]
        batch_targets.append(entry)

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump({"targets": batch_targets}, f, default_flow_style=False)
        batch_path = f.name

    # Output dir
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = BATCH_DIR / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    corvus = _corvus_bin()
    cmd = [corvus, "batch", batch_path, "--output-dir", str(output_dir), "--sarif"]
    if args.min_confidence:
        cmd += ["--min-confidence", str(args.min_confidence)]

    print(f"$ {' '.join(cmd)}\n")
    subprocess.run(cmd, check=False)

    # Update state
    names = {t["name"] for t in selected}
    updated = _update_from_dir(output_dir, data, names)
    _save(data)

    print(f"\nState updated ({updated} targets). Output: {output_dir}")
    print(f"Run 'python cs01.py status' to see results.")


def cmd_update(args: argparse.Namespace, data: dict) -> None:
    output_dir = Path(args.output_dir)
    if not output_dir.exists():
        print(f"ERROR: {output_dir} does not exist")
        sys.exit(1)
    names = {t["name"] for t in data["targets"]}
    updated = _update_from_dir(output_dir, data, names)
    _save(data)
    print(f"Updated {updated} targets from {output_dir}")


def cmd_add(args: argparse.Namespace, data: dict) -> None:
    existing = {t["name"] for t in data["targets"]}
    if args.name in existing:
        print(f"ERROR: target '{args.name}' already exists")
        sys.exit(1)

    new: dict = {
        "name": args.name,
        "tier": args.tier,
        "transport": args.transport or "stdio",
        "status": "pending",
    }
    if args.cmd:
        new["cmd"] = args.cmd
    if args.url:
        new["url"] = args.url
    if args.notes:
        new["notes"] = args.notes

    data["targets"].append(new)
    _save(data)
    print(f"Added '{args.name}' (tier {args.tier}, status=pending)")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cs01",
        description="CS01 MCP Ecosystem Audit — target tracker",
    )
    sub = parser.add_subparsers(dest="cmd", metavar="command")

    sub.add_parser("status", help="Show target state table")

    p_scan = sub.add_parser("scan", help="Run corvus batch on pending targets")
    p_scan.add_argument("--tier", metavar="A|B|C", help="Filter by tier")
    p_scan.add_argument("--name", metavar="NAME", help="Scan a single target by name")
    p_scan.add_argument("--all", action="store_true", help="Include already-done targets")
    p_scan.add_argument("--redone", action="store_true", help="Re-scan only done targets (excludes skip)")
    p_scan.add_argument("--exclude", nargs="+", metavar="NAME", help="Exclude specific targets by name")
    p_scan.add_argument("--min-confidence", type=int, metavar="N", help="Pass --min-confidence to corvus")

    p_update = sub.add_parser("update", help="Update state from existing corvus output dir")
    p_update.add_argument("output_dir", help="Path to corvus batch output dir")

    p_add = sub.add_parser("add", help="Add a new target")
    p_add.add_argument("name", help="Target name (e.g. mcp-my-server)")
    p_add.add_argument("--tier", required=True, choices=["A", "B", "C"])
    p_add.add_argument("--transport", choices=["stdio", "http"])
    p_add.add_argument("--cmd", nargs="+", metavar="ARG")
    p_add.add_argument("--url", metavar="URL")
    p_add.add_argument("--notes", metavar="TEXT")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return

    data = _load()
    {"status": cmd_status, "scan": cmd_scan, "update": cmd_update, "add": cmd_add}[args.cmd](args, data)


if __name__ == "__main__":
    main()

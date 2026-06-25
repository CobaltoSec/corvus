"""A1: Batch scan mode — run Corvus scans against multiple targets from a YAML config."""
from __future__ import annotations

import asyncio
import shlex
import sys
from pathlib import Path
from typing import Any

import yaml

from .core.models import Severity
from .core.session import ScanSession
from .discovery.enumerator import MCPEnumerator
from .modules.dynamic.token_exposure import TokenExposureModule
from .modules.dynamic.cmd_injection import CmdInjectionModule
from .modules.dynamic.response_flood import ResponseFloodModule
from .modules.dynamic.rug_pull import RugPullModule
from .modules.dynamic.schema_bypass import SchemaBypassModule
from .modules.static.auth_audit import AuthAuditModule
from .modules.static.log_audit import LogAuditModule
from .modules.static.schema_audit import SchemaAuditModule
from .modules.static.scope_audit import ScopeAuditModule
from .modules.static.shadow_tool import ShadowToolModule
from .modules.static.supply_chain import SupplyChainModule
from .modules.static.tool_poisoning import ToolPoisoningModule
from .reporting.report import ReportGenerator
from .transport.http import HttpTransport
from .transport.stdio import StdioTransport

_ALL_MODULES = [
    ScopeAuditModule, SupplyChainModule,
    ToolPoisoningModule, SchemaAuditModule, ShadowToolModule,
    AuthAuditModule, LogAuditModule, CmdInjectionModule,
    TokenExposureModule, SchemaBypassModule, ResponseFloodModule, RugPullModule,
]


class BatchTarget:
    def __init__(self, name: str, transport: str, cmd: list[str] | None, url: str | None):
        self.name = name
        self.transport = transport
        self.cmd = cmd
        self.url = url


class BatchResult:
    def __init__(self):
        self.targets: list[dict[str, Any]] = []

    def add(self, name: str, transport: str, finding_count: dict[str, int]) -> None:
        self.targets.append({
            "name": name,
            "transport": transport,
            "finding_count": finding_count,
        })

    def summary_md(self) -> str:
        lines = ["# Corvus Batch Scan Summary", ""]
        lines.append("| Target | CRITICAL | HIGH | MEDIUM | LOW | INFO | Total |")
        lines.append("|--------|----------|------|--------|-----|------|-------|")
        for t in self.targets:
            fc = t["finding_count"]
            if "error" in fc:
                lines.append(f"| {t['name']} | ERROR | — | — | — | — | — |")
                continue
            total = sum(fc.values())
            lines.append(
                f"| {t['name']} "
                f"| {fc.get('critical', 0)} "
                f"| {fc.get('high', 0)} "
                f"| {fc.get('medium', 0)} "
                f"| {fc.get('low', 0)} "
                f"| {fc.get('info', 0)} "
                f"| {total} |"
            )
        return "\n".join(lines)


def load_batch_targets(config_path: Path) -> list[BatchTarget]:
    """Parse a targets YAML file and return a list of BatchTarget objects."""
    with open(config_path) as f:
        data = yaml.safe_load(f)

    targets = data.get("targets", [])
    if not isinstance(targets, list):
        raise ValueError("targets.yaml must have a 'targets' list")

    result: list[BatchTarget] = []
    for entry in targets:
        if "name" not in entry:
            raise ValueError(f"Each target must have a 'name' field: {entry}")
        if "transport" not in entry:
            raise ValueError(f"Target '{entry.get('name')}' must have a 'transport' field")

        transport = entry["transport"]
        cmd: list[str] | None = None
        url: str | None = None

        if transport == "stdio":
            raw_cmd = entry.get("cmd")
            if raw_cmd is None:
                raise ValueError(f"Target '{entry['name']}' with stdio transport must have a 'cmd' field")
            if isinstance(raw_cmd, str):
                cmd = shlex.split(raw_cmd, posix=(sys.platform != "win32"))
            else:
                cmd = list(raw_cmd)
        elif transport == "http":
            url = entry.get("url")
            if url is None:
                raise ValueError(f"Target '{entry['name']}' with http transport must have a 'url' field")
        else:
            raise ValueError(f"Unknown transport '{transport}' in target '{entry['name']}'")

        result.append(BatchTarget(name=entry["name"], transport=transport, cmd=cmd, url=url))

    return result


async def run_batch(
    targets: list[BatchTarget],
    output_dir: Path,
    *,
    timeout: int = 30,
    min_confidence: int | None = None,
    sarif: bool = False,
) -> BatchResult:
    batch_result = BatchResult()

    for target in targets:
        target_dir = output_dir / target.name
        target_dir.mkdir(parents=True, exist_ok=True)

        if target.transport == "stdio":
            xport = StdioTransport(target.cmd or [], timeout=timeout)
        else:
            xport = HttpTransport(target.url or "", timeout=timeout)

        try:
            async with xport:
                session = ScanSession(
                    target=" ".join(target.cmd) if target.cmd else target.url or "",
                    transport=target.transport,
                    output_dir=target_dir,
                )
                surface = await MCPEnumerator(xport).enumerate()

                for mod_cls in _ALL_MODULES:
                    mod = mod_cls()
                    findings = await mod.run(surface, xport, session)
                    for f in findings:
                        session.add_finding(f)

                if min_confidence is not None:
                    session.findings = [f for f in session.findings if f.confidence >= min_confidence]

                scan_result = session.to_result(surface, [m().name for m in _ALL_MODULES])
                gen = ReportGenerator(target_dir)
                gen.write(scan_result)
                if sarif:
                    gen.write_sarif(scan_result)

                batch_result.add(target.name, target.transport, scan_result.finding_count)
        except Exception as e:
            batch_result.add(target.name, target.transport, {"error": str(e)})

    return batch_result

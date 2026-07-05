"""A1: Batch scan mode — run Corvus scans against multiple targets from a YAML config."""
from __future__ import annotations

import asyncio
import shlex
import sys
from pathlib import Path
from typing import Any

# ── Windows pipe noise suppression ───────────────────────────────────────────
# When StdioTransport kills a subprocess via taskkill /F /T, asyncio's
# ProactorEventLoop emits two types of stderr noise on Windows:
#   1. "socket.send() raised exception" — loop.call_exception_handler() fires
#      when asyncio tries to write to a pipe whose OS handle is already closed.
#   2. "Exception ignored in _ProactorBasePipeTransport.__del__" — Python's
#      unraisablehook fires when transport GC runs with open pipe handles.
# Neither indicates a real bug; both are expected cleanup artifacts.

_orig_unraisablehook = sys.unraisablehook


def _filtered_unraisablehook(unraisable: sys.UnraisableHookArgs) -> None:
    obj_type = type(unraisable.object).__name__ if unraisable.object is not None else ""
    exc_str = str(unraisable.exc_value) if unraisable.exc_value is not None else ""
    if "ProactorBasePipeTransport" in obj_type or "I/O operation on closed pipe" in exc_str:
        return
    _orig_unraisablehook(unraisable)


def _filtered_exception_handler(loop: asyncio.AbstractEventLoop, context: dict) -> None:
    msg = context.get("message", "")
    if "socket.send() raised exception" in msg:
        return
    loop.default_exception_handler(context)

import yaml

from .core.models import Severity, ScanResult
from .core.session import ScanSession
from .scoring import compute_risk_score
from .discovery.enumerator import MCPEnumerator
from .modules.dynamic.batch_dos import BatchDosModule
from .modules.dynamic.cancellation_probe import CancellationProbeModule
from .modules.dynamic.completion_probe import CompletionProbeModule
from .modules.dynamic.cursor_probe import CursorProbeModule
from .modules.dynamic.elicitation_probe import ElicitationProbeModule
from .modules.dynamic.logging_probe import LoggingProbeModule
from .modules.dynamic.oauth_bypass import OAuthBypassModule
from .modules.dynamic.prompts_injection import PromptsInjectionModule
from .modules.dynamic.sampling_probe import SamplingProbeModule
from .modules.dynamic.token_exposure import TokenExposureModule
from .modules.dynamic.cmd_injection import CmdInjectionModule
from .modules.dynamic.response_flood import ResponseFloodModule
from .modules.dynamic.rug_pull import RugPullModule
from .modules.dynamic.schema_bypass import SchemaBypassModule
from .modules.dynamic.ssrf import SSRFModule
from .modules.dynamic.endpoint_probe import EndpointProbeModule
from .modules.dynamic.param_smuggling import ParamSmugglingModule
from .modules.dynamic.init_audit import InitAuditModule
from .modules.dynamic.proto_fuzz import ProtoFuzzModule
from .modules.dynamic.output_encoding import OutputEncodingModule
from .modules.dynamic.response_injection import ResponseInjectionModule
from .modules.static.auth_audit import AuthAuditModule
from .modules.static.github_advisory import GitHubAdvisoryModule
from .modules.static.log_audit import LogAuditModule
from .modules.static.npm_behavior import NpmBehaviorModule
from .modules.static.osv_supply_chain import OsvSupplyChainModule
from .modules.static.resource_uri import ResourceUriModule
from .modules.static.schema_audit import SchemaAuditModule
from .modules.static.scope_audit import ScopeAuditModule
from .modules.static.shadow_tool import ShadowToolModule
from .modules.static.supply_chain import SupplyChainModule
from .modules.static.supply_chain_python import SupplyChainPythonModule
from .modules.static.tool_chaining import ToolChainingModule
from .modules.static.tool_poisoning import ToolPoisoningModule
from .reporting.report import ReportGenerator
from .transport.http import HttpTransport
from .transport.stdio import StdioTransport

_ALL_MODULES = [
    ScopeAuditModule, SupplyChainModule, SupplyChainPythonModule, OsvSupplyChainModule,
    GitHubAdvisoryModule, NpmBehaviorModule,
    ToolPoisoningModule, SchemaAuditModule, ShadowToolModule,
    AuthAuditModule, LogAuditModule, ResourceUriModule, ToolChainingModule,
    BatchDosModule, CmdInjectionModule, TokenExposureModule, SchemaBypassModule,
    ResponseFloodModule, RugPullModule, SSRFModule, EndpointProbeModule,
    ParamSmugglingModule, InitAuditModule, ProtoFuzzModule,
    OutputEncodingModule, ResponseInjectionModule, OAuthBypassModule,
    SamplingProbeModule, ElicitationProbeModule,
    CompletionProbeModule, LoggingProbeModule, PromptsInjectionModule,
    CursorProbeModule, CancellationProbeModule,
]

# Max number of targets scanned concurrently.
_BATCH_CONCURRENCY = 5


class BatchTarget:
    def __init__(
        self,
        name: str,
        transport: str,
        cmd: list[str] | None,
        url: str | None,
        env_vars: dict[str, str] | None = None,
    ):
        self.name = name
        self.transport = transport
        self.cmd = cmd
        self.url = url
        self.env_vars = env_vars


class BatchResult:
    def __init__(self):
        self.targets: list[dict[str, Any]] = []

    def add(self, name: str, transport: str, finding_count: dict[str, int], risk_score: int | None = None) -> None:
        self.targets.append({
            "name": name,
            "transport": transport,
            "finding_count": finding_count,
            "risk_score": risk_score,
        })

    def summary_md(self) -> str:
        lines = ["# Corvus Batch Scan Summary", ""]
        lines.append("| Target | CRITICAL | HIGH | MEDIUM | LOW | INFO | Total | Score |")
        lines.append("|--------|----------|------|--------|-----|------|-------|-------|")
        for t in self.targets:
            fc = t["finding_count"]
            if "error" in fc:
                lines.append(f"| {t['name']} | ERROR | — | — | — | — | — | — |")
                continue
            if "skipped" in fc:
                lines.append(f"| {t['name']} | SKIP | — | — | — | — | — | — |")
                continue
            total = sum(fc.values())
            score = t.get("risk_score")
            score_str = f"{score}/100" if score is not None else "—"
            lines.append(
                f"| {t['name']} "
                f"| {fc.get('critical', 0)} "
                f"| {fc.get('high', 0)} "
                f"| {fc.get('medium', 0)} "
                f"| {fc.get('low', 0)} "
                f"| {fc.get('info', 0)} "
                f"| {total} "
                f"| {score_str} |"
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
        if entry.get("status") in ("skip", "done", "error"):
            continue
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

        env_vars = entry.get("env_vars") or None
        if env_vars is not None and not isinstance(env_vars, dict):
            raise ValueError(f"Target '{entry['name']}': env_vars must be a dict")

        result.append(BatchTarget(name=entry["name"], transport=transport, cmd=cmd, url=url, env_vars=env_vars))

    return result


_TARGET_SCAN_TIMEOUT = 600  # seconds — hard cap per target regardless of per-request timeouts


def _resolve_batch_modules(modules: list[str] | None) -> list[type]:
    """Return the subset of _ALL_MODULES matching the given names (or all if None)."""
    if not modules:
        return _ALL_MODULES
    registry = {cls().name: cls for cls in _ALL_MODULES}
    result: list[type] = []
    for name in modules:
        if name == "all":
            return _ALL_MODULES
        if name == "static":
            return [cls for cls in _ALL_MODULES if cls().is_static]
        if name == "dynamic":
            return [cls for cls in _ALL_MODULES if not cls().is_static]
        if name in registry:
            result.append(registry[name])
    return result or _ALL_MODULES


async def _scan_one(
    target: BatchTarget,
    output_dir: Path,
    *,
    timeout: int,
    target_timeout: int,
    min_confidence: int | None,
    sarif: bool,
    sem: asyncio.Semaphore,
    skip_existing: bool,
    modules: list[str] | None = None,
) -> tuple[str, str, dict, int | None, ScanResult | None]:
    """Scan one target. Returns (name, transport, finding_count, risk_score, scan_result)."""
    target_dir = output_dir / target.name

    if skip_existing and (target_dir / "report.json").exists():
        return target.name, target.transport, {"skipped": True}, None, None

    target_dir.mkdir(parents=True, exist_ok=True)

    if target.transport == "stdio":
        xport = StdioTransport(target.cmd or [], timeout=timeout, env=target.env_vars)
    else:
        xport = HttpTransport(target.url or "", timeout=timeout)

    active_modules = _resolve_batch_modules(modules)

    async with sem:
        try:
            async with asyncio.timeout(target_timeout):
                async with xport:
                    session = ScanSession(
                        target=" ".join(target.cmd) if target.cmd else target.url or "",
                        transport=target.transport,
                        output_dir=target_dir,
                    )
                    surface = await MCPEnumerator(xport).enumerate()

                    for mod_cls in active_modules:
                        mod = mod_cls()
                        findings = await mod.run(surface, xport, session)
                        for f in findings:
                            session.add_finding(f)

                    if min_confidence is not None:
                        session.findings = [f for f in session.findings if f.confidence >= min_confidence]

                    scan_result = session.to_result(surface, [m().name for m in active_modules])
                    gen = ReportGenerator(target_dir)
                    gen.write(scan_result)
                    if sarif:
                        gen.write_sarif(scan_result)

                    risk_score = compute_risk_score(scan_result.findings)
                    return target.name, target.transport, scan_result.finding_count, risk_score, scan_result
        except Exception as e:
            return target.name, target.transport, {"error": str(e)}, None, None


async def run_batch(
    targets: list[BatchTarget],
    output_dir: Path,
    *,
    timeout: int = 30,
    target_timeout: int = _TARGET_SCAN_TIMEOUT,
    min_confidence: int | None = None,
    sarif: bool = False,
    skip_existing: bool = False,
    modules: list[str] | None = None,
) -> BatchResult:
    if sys.platform == "win32":
        sys.unraisablehook = _filtered_unraisablehook
        asyncio.get_running_loop().set_exception_handler(_filtered_exception_handler)

    sem = asyncio.Semaphore(_BATCH_CONCURRENCY)

    coros = [
        _scan_one(
            target, output_dir,
            timeout=timeout,
            target_timeout=target_timeout,
            min_confidence=min_confidence,
            sarif=sarif,
            sem=sem,
            skip_existing=skip_existing,
            modules=modules,
        )
        for target in targets
    ]

    gathered = await asyncio.gather(*coros)

    batch_result = BatchResult()
    named_scans: list[tuple[str, ScanResult]] = []

    for name, transport, finding_count, risk_score, scan_result in gathered:
        batch_result.add(name, transport, finding_count, risk_score=risk_score)
        if scan_result is not None:
            named_scans.append((name, scan_result))

    if sarif and named_scans:
        from .reporting.report import write_combined_sarif
        write_combined_sarif(named_scans, output_dir)

    return batch_result

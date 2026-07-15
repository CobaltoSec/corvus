from __future__ import annotations

import asyncio
import datetime
import shlex
import sys
import time
from pathlib import Path
from typing import Annotated, List, Optional

try:
    from cobalt_hub_client import emit as _hub_emit
except ImportError:
    _hub_emit = None

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .config import CorvusConfig, load_config
from .core.models import Severity
from .core.session import ScanSession
from .discovery.enumerator import MCPEnumerator
from .modules.dynamic.batch_dos import BatchDosModule
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
from .modules.dynamic.elicitation_probe import ElicitationProbeModule
from .modules.dynamic.oauth_bypass import OAuthBypassModule
from .modules.dynamic.completion_probe import CompletionProbeModule
from .modules.dynamic.logging_probe import LoggingProbeModule
from .modules.dynamic.prompts_injection import PromptsInjectionModule
from .modules.dynamic.cursor_probe import CursorProbeModule
from .modules.dynamic.cancellation_probe import CancellationProbeModule
from .modules.dynamic.response_injection import ResponseInjectionModule
from .modules.dynamic.sampling_probe import SamplingProbeModule
from .modules.static.auth_audit import AuthAuditModule
from .modules.static.log_audit import LogAuditModule
from .modules.static.schema_audit import SchemaAuditModule
from .modules.static.resource_uri import ResourceUriModule
from .modules.static.scope_audit import ScopeAuditModule
from .modules.static.shadow_tool import ShadowToolModule
from .modules.static.github_advisory import GitHubAdvisoryModule
from .modules.static.npm_behavior import NpmBehaviorModule
from .modules.static.osv_supply_chain import OsvSupplyChainModule
from .modules.static.supply_chain import SupplyChainModule
from .modules.static.supply_chain_python import SupplyChainPythonModule
from .modules.static.tool_chaining import ToolChainingModule
from .modules.static.tool_poisoning import ToolPoisoningModule
from .plugins import discover_plugins
from .reporting.report import ReportGenerator
from .transport.http import HttpTransport
from .transport.stdio import StdioTransport

app = typer.Typer(name="corvus", help="MCP server security testing framework", add_completion=False)
console = Console()

# Built-in modules in canonical OWASP order. Plugins are merged at runtime.
_ALL_MODULES = {
    "scope-audit":     ScopeAuditModule,
    "supply-chain":        SupplyChainModule,
    "supply-chain-python": SupplyChainPythonModule,
    "osv-supply-chain":    OsvSupplyChainModule,
    "github-advisory":     GitHubAdvisoryModule,
    "npm-behavior":        NpmBehaviorModule,
    "tool-poisoning":  ToolPoisoningModule,
    "schema-audit":    SchemaAuditModule,
    "shadow-tool":     ShadowToolModule,
    "auth-audit":      AuthAuditModule,
    "log-audit":       LogAuditModule,
    "resource-uri":    ResourceUriModule,
    "tool-chaining":   ToolChainingModule,
    "batch-dos":       BatchDosModule,
    "cmd-injection":   CmdInjectionModule,
    "token-exposure":  TokenExposureModule,
    "schema-bypass":   SchemaBypassModule,
    "response-flood":  ResponseFloodModule,
    "rug-pull":        RugPullModule,
    "ssrf":            SSRFModule,
    "endpoint-probe":  EndpointProbeModule,
    "param-smuggling": ParamSmugglingModule,
    "init-audit":      InitAuditModule,
    "proto-fuzz":      ProtoFuzzModule,
    "output-encoding":      OutputEncodingModule,
    "response-injection":   ResponseInjectionModule,
    "oauth-bypass":         OAuthBypassModule,
    "sampling-probe":       SamplingProbeModule,
    "elicitation-probe":    ElicitationProbeModule,
    "completion-probe":     CompletionProbeModule,
    "logging-probe":        LoggingProbeModule,
    "prompts-injection":    PromptsInjectionModule,
    "cursor-probe":         CursorProbeModule,
    "cancellation-probe":   CancellationProbeModule,
}
_STATIC  = {"scope-audit", "supply-chain", "supply-chain-python", "osv-supply-chain", "github-advisory", "npm-behavior", "tool-poisoning", "schema-audit", "shadow-tool", "auth-audit", "log-audit", "resource-uri", "tool-chaining"}
_DYNAMIC = {
    "batch-dos", "cmd-injection", "token-exposure", "schema-bypass", "response-flood", "rug-pull",
    "ssrf", "endpoint-probe", "param-smuggling", "init-audit", "proto-fuzz",
    "output-encoding", "response-injection", "oauth-bypass",
    "sampling-probe", "elicitation-probe",
    "completion-probe", "logging-probe", "prompts-injection", "cursor-probe", "cancellation-probe",
}

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _print_banner() -> None:
    if not console.is_terminal:
        return
    console.print(
        f"\n[bold cyan]CORVUS[/bold cyan] [dim]v{__version__}[/dim]"
        "  ·  MCP Security Framework  ·  [dim]CobaltoSec[/dim]\n"
    )


class _NoiseFilter:
    """Swallow asyncio Windows pipe-cleanup noise lines written to stderr."""
    _SUPPRESS = ("socket.send() raised exception", "Exception ignored in _Proactor")

    def __init__(self, real: object) -> None:
        self._real = real
        self._buf = ""

    def write(self, text: str) -> int:
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if not any(s in line for s in self._SUPPRESS):
                self._real.write(line + "\n")
        return len(text)

    def flush(self) -> None:
        if self._buf and not any(s in self._buf for s in self._SUPPRESS):
            self._real.write(self._buf)
        self._buf = ""
        self._real.flush()

    def fileno(self) -> int:
        return self._real.fileno()
_SEV_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "blue",
    "info":     "dim",
}

# ── S2: inline target helpers ─────────────────────────────────────────────────

_RUNNERS = {"npx", "uvx", "python", "python3", "node", "deno", "bun", "py"}


def _name_from_cmd(cmd_str: str) -> str:
    """Derive a short target name from a stdio command string."""
    parts = shlex.split(cmd_str, posix=(sys.platform != "win32"))
    if not parts:
        return "target"
    i = 0
    while i < len(parts) and parts[i].lower() in _RUNNERS:
        i += 1
    if i < len(parts) and parts[i] == "-m" and i + 1 < len(parts):
        return parts[i + 1].split(".")[0]
    while i < len(parts) and parts[i].startswith("-"):
        i += 1
    token = parts[i] if i < len(parts) else parts[0]
    # Strip @scope/pkg → pkg and path separators
    return token.rsplit("/", 1)[-1].split("\\")[-1]


def _name_from_url(url: str) -> str:
    """Derive a short target name from an HTTP URL."""
    from urllib.parse import urlparse
    p = urlparse(url)
    host = p.hostname or "target"
    return f"{host}-{p.port}" if p.port else host


def _build_inline_targets(stdio_cmds: list[str], http_urls: list[str]) -> list:
    """Convert --stdio / --http CLI strings to BatchTarget objects."""
    from .batch import BatchTarget

    seen: dict[str, int] = {}

    def unique(raw: str) -> str:
        if raw not in seen:
            seen[raw] = 1
            return raw
        seen[raw] += 1
        return f"{raw}-{seen[raw]}"

    targets = []
    for cmd_str in stdio_cmds:
        name = unique(_name_from_cmd(cmd_str))
        cmd = shlex.split(cmd_str, posix=(sys.platform != "win32"))
        targets.append(BatchTarget(name=name, transport="stdio", cmd=cmd, url=None))
    for url in http_urls:
        name = unique(_name_from_url(url))
        targets.append(BatchTarget(name=name, transport="http", cmd=None, url=url))
    return targets


# ── S4: Rich live progress for batch ─────────────────────────────────────────

async def _run_batch_with_progress(
    targets: list,
    output_dir: Path,
    *,
    timeout: int,
    target_timeout: int,
    min_confidence: int | None,
    sarif: bool,
    modules: list[str] | None,
    concurrency: int,
):
    from .batch import run_batch
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    with Progress(
        SpinnerColumn(finished_text=" "),
        TextColumn("[bold]{task.description}"),
        TextColumn("{task.fields[status]}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task_ids: dict[str, int] = {}
        for t in targets:
            tid = progress.add_task(t.name, total=1, status="[dim]·  queued[/dim]")
            task_ids[t.name] = tid

        def on_status(name: str, status: str, detail: dict) -> None:
            tid = task_ids.get(name)
            if tid is None:
                return
            if status == "start":
                progress.update(tid, status="[cyan]scanning…[/cyan]")
            elif status == "done":
                fc = detail.get("finding_count", {})
                parts = []
                for sev, abbr, color in [
                    ("critical", "C", "bold red"),
                    ("high", "H", "red"),
                    ("medium", "M", "yellow"),
                    ("low", "L", "blue"),
                    ("info", "I", "dim"),
                ]:
                    n = fc.get(sev, 0)
                    if n:
                        parts.append(f"[{color}]{n}{abbr}[/{color}]")
                findings_str = " ".join(parts) if parts else "[dim]clean[/dim]"
                score = detail.get("risk_score")
                score_str = f"  [dim]({score}/100)[/dim]" if score is not None else ""
                progress.update(tid, completed=1, status=f"[green]✓[/green]  {findings_str}{score_str}")
            elif status == "error":
                err = str(detail.get("error", ""))[:60]
                progress.update(tid, completed=1, status=f"[red]✗  {err}[/red]")
            elif status == "skipped":
                progress.update(tid, completed=1, status="[dim]—  skipped[/dim]")

        result = await run_batch(
            targets, output_dir,
            timeout=timeout,
            target_timeout=target_timeout,
            min_confidence=min_confidence,
            sarif=sarif,
            modules=modules,
            concurrency=concurrency,
            on_status=on_status,
        )

    return result


@app.command()
def scan(
    target: Annotated[Optional[str], typer.Argument(
        help="Target: URL (http) or launch command (stdio). "
             "E.g. 'npx @modelcontextprotocol/server-everything' or 'http://localhost:3000/mcp'"
    )] = None,
    transport: Annotated[Optional[str], typer.Option(
        "--transport", "-t", help="stdio | http (overrides auto-detect)")] = None,
    cmd: Annotated[Optional[str], typer.Option(
        "--cmd", help="Command to launch MCP server (stdio)")] = None,
    url: Annotated[Optional[str], typer.Option(
        "--url", help="URL of MCP server (http)")] = None,
    module: Annotated[Optional[str], typer.Option(
        "--module", "-m",
        help="all | static | dynamic | <module-name> (overrides config)")] = None,
    output_dir: Annotated[Optional[Path], typer.Option("--output-dir", "-o")] = None,
    fail_on: Annotated[Optional[str], typer.Option(
        "--fail-on",
        help="Exit 1 if findings at this severity or above (critical|high|medium|low)")] = None,
    timeout: Annotated[Optional[int], typer.Option(
        "--timeout", help="Request timeout in seconds (overrides config)")] = None,
    sarif: Annotated[bool, typer.Option(
        "--sarif", help="Also write SARIF 2.1.0 report")] = False,
    log_requests: Annotated[bool, typer.Option(
        "--log-requests", help="Write raw JSON-RPC exchanges to exchanges.jsonl")] = False,
    header: Annotated[Optional[list[str]], typer.Option(
        "--header", help='HTTP header "Key: Value" (repeatable, for http transport)')] = None,
    config_file: Annotated[Optional[Path], typer.Option(
        "--config", "-c", help="Path to corvus.toml config file")] = None,
    plugin_dir: Annotated[Optional[list[str]], typer.Option(
        "--plugin-dir", help="Directory to load external modules from (repeatable)")] = None,
    min_confidence: Annotated[Optional[int], typer.Option(
        "--min-confidence",
        help="Exclude findings below this confidence score (0-100)")] = None,
    env: Annotated[Optional[list[str]], typer.Option(
        "--env",
        help='Environment variable "KEY=VAL" for the MCP subprocess (repeatable, stdio only)')] = None,
    delay: Annotated[float, typer.Option(
        "--delay", help="Seconds to wait between probes (rate limiting / WAF)")] = 0.0,
    show_score: Annotated[bool, typer.Option(
        "--score", help="Print Risk Score (0-100) at end of scan")] = False,
    fast: Annotated[bool, typer.Option(
        "--fast", "-F", help="Fast mode: static modules only (no live probes)")] = False,
):
    """Scan an MCP server for security vulnerabilities."""
    asyncio.run(_scan(
        target, transport, cmd, url, module, output_dir, fail_on, timeout,
        sarif, log_requests, header, config_file, plugin_dir, min_confidence,
        env, delay, show_score, fast,
    ))


async def _scan(
    cli_target: str | None,
    cli_transport: str | None,
    cli_cmd: str | None,
    cli_url: str | None,
    cli_module: str | None,
    output_dir: Path | None,
    cli_fail_on: str | None,
    cli_timeout: int | None,
    cli_sarif: bool,
    cli_log_requests: bool,
    raw_headers: list[str] | None,
    config_file: Path | None,
    cli_plugin_dirs: list[str] | None,
    min_confidence: int | None = None,
    cli_env: list[str] | None = None,
    delay: float = 0.0,
    show_score: bool = False,
    fast: bool = False,
) -> None:
    if sys.platform == "win32":
        from .batch import _filtered_unraisablehook, _filtered_exception_handler
        sys.unraisablehook = _filtered_unraisablehook
        asyncio.get_running_loop().set_exception_handler(_filtered_exception_handler)

    # --- Load config (all fields have defaults) ---
    cfg: CorvusConfig
    if config_file:
        try:
            cfg = load_config(config_file)
        except FileNotFoundError:
            console.print(f"[red]Config file not found: {config_file}[/red]")
            raise typer.Exit(1)
        except Exception as exc:
            console.print(f"[red]Invalid config file: {exc}[/red]")
            raise typer.Exit(1)
    else:
        cfg = CorvusConfig()

    # --- Auto-detect transport from positional target ---
    if cli_target:
        if cli_target.startswith(("http://", "https://")):
            cli_transport = cli_transport or "http"
            cli_url = cli_url or cli_target
        else:
            cli_transport = cli_transport or "stdio"
            cli_cmd = cli_cmd or cli_target

    # --- Merge: CLI overrides config; config fills what CLI omits ---
    transport_name = cli_transport or cfg.scan.transport
    cmd            = cli_cmd or cfg.scan.cmd
    url            = cli_url or cfg.scan.url
    timeout        = cli_timeout if cli_timeout is not None else cfg.scan.timeout
    fail_on        = cli_fail_on or cfg.scan.fail_on
    write_sarif    = cli_sarif or cfg.scan.sarif
    output_dir_str = str(output_dir) if output_dir else cfg.scan.output_dir

    # Modules: CLI string takes full precedence; --fast forces static; config fills remainder
    if cli_module:
        module_filter: str | list[str] = cli_module
    elif fast:
        module_filter = "static"
    else:
        module_filter = cfg.scan.modules  # "all" | "static" | "dynamic" | list[str]

    # Headers: start from config, then CLI overrides per key
    merged_headers: dict[str, str] = dict(cfg.scan.headers)
    for h in (raw_headers or []):
        if ":" in h:
            k, _, v = h.partition(":")
            merged_headers[k.strip()] = v.strip()

    # Plugin dirs: union of CLI dirs + config dirs
    all_plugin_dirs = list(cli_plugin_dirs or []) + cfg.scan.plugin_dirs

    # Env vars: config base, CLI overrides per key
    merged_env: dict[str, str] = dict(cfg.scan.env)
    for e in (cli_env or []):
        if "=" in e:
            k, _, v = e.partition("=")
            merged_env[k] = v

    # Delay: CLI takes precedence over config
    effective_delay = delay if delay else cfg.scan.delay

    # Output directory
    if output_dir_str:
        resolved_output_dir = Path(output_dir_str)
    else:
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        resolved_output_dir = Path("corvus-sessions") / f"scan-{ts}"

    # --- Build transport ---
    if transport_name == "stdio":
        if not cmd:
            console.print("[red]--cmd is required for stdio transport (or set scan.cmd in config)[/red]")
            raise typer.Exit(1)
        xport = StdioTransport(
            shlex.split(cmd, posix=(sys.platform != "win32")),
            timeout=timeout,
            log_requests=cli_log_requests,
            env=merged_env or None,
        )
        target = cmd
    elif transport_name == "http":
        if not url:
            console.print("[red]--url is required for http transport (or set scan.url in config)[/red]")
            raise typer.Exit(1)
        xport = HttpTransport(url, timeout=timeout, headers=merged_headers or None, log_requests=cli_log_requests)
        target = url
    else:
        console.print(f"[red]Unknown transport: {transport_name}[/red]")
        raise typer.Exit(1)

    # --- Discover plugins and build final module registry ---
    plugins = discover_plugins(plugin_dirs=all_plugin_dirs or None)
    modules_registry = {**_ALL_MODULES, **plugins}  # plugins override built-ins by name
    if plugins:
        console.print(f"[dim]Loaded {len(plugins)} plugin(s): {', '.join(plugins)}[/dim]")

    # --- Resolve module list ---
    names = _resolve_modules(module_filter, modules_registry)
    if names is None:
        raise typer.Exit(1)

    session = ScanSession(target=target, transport=transport_name, output_dir=resolved_output_dir)

    _print_banner()
    mod_label = (
        f"{len(names)} ({module_filter})"
        if isinstance(module_filter, str)
        else f"{len(names)} (custom)"
    )
    panel_lines = [
        f"[bold]Target[/bold]    {target}",
        f"[bold]Modules[/bold]   {mod_label}",
    ]
    if config_file:
        panel_lines.append(f"[bold]Config[/bold]    {config_file}")
    if effective_delay:
        panel_lines.append(f"[bold]Delay[/bold]     {effective_delay}s")
    console.print(Panel("\n".join(panel_lines), title="Scan", border_style="dim", padding=(0, 1)))
    console.print()

    t0 = time.monotonic()
    if sys.platform == "win32":
        _orig_stderr, sys.stderr = sys.stderr, _NoiseFilter(sys.stderr)
    else:
        _orig_stderr = None
    try:
        async with xport:
            console.print("[dim]Enumerating surface...[/dim]", end=" ")
            surface = await MCPEnumerator(xport).enumerate()
            parts = [f"{len(surface.tools)} tools", f"{len(surface.resources)} resources", f"{len(surface.prompts)} prompts"]
            if surface.server_name:
                parts.append(f"{surface.server_name} {surface.server_version}".strip())
            console.print(f"[dim]{' · '.join(parts)}[/dim]")
            console.print()

            total = len(names)
            for i, name in enumerate(names, 1):
                mod = modules_registry[name]()
                findings = await mod.run(surface, xport, session)
                for f in findings:
                    session.add_finding(f)
                if findings:
                    n = len(findings)
                    badge = f" [dim]({n})[/dim]" if n > 1 else ""
                    console.print(f"[dim][{i:>2}/{total}][/dim] [bold]{name}[/bold]{badge}")
                    for f in findings:
                        color = _SEV_COLOR.get(f.severity.value, "white")
                        title = f.title if len(f.title) <= 90 else f.title[:87] + "…"
                        console.print(
                            f"       [{color}]{f.severity.value.upper()}[/{color}]"
                            f"  {title} [dim]({f.confidence}%)[/dim]"
                        )
                else:
                    console.print(f"[dim][{i:>2}/{total}]  {name}[/dim]")
                if effective_delay:
                    await asyncio.sleep(effective_delay)
    finally:
        if _orig_stderr is not None:
            sys.stderr.flush()
            sys.stderr = _orig_stderr

    if min_confidence is not None:
        session.findings = [f for f in session.findings if f.confidence >= min_confidence]

    result = session.to_result(
        surface, names,
        exchanges=list(xport.exchanges) if cli_log_requests else [],
    )
    gen = ReportGenerator(resolved_output_dir)
    report_path = gen.write(result)

    elapsed = time.monotonic() - t0
    console.print()
    _print_summary(result)

    if show_score:
        from .scoring import compute_risk_score, risk_tier
        sc = compute_risk_score(result.findings)
        tier = risk_tier(sc)
        _TIER_COLOR = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "CLEAR": "green"}
        tc = _TIER_COLOR.get(tier, "white")
        console.print(f"Risk Score : [{tc}]{sc}/100 — {tier}[/{tc}]")

    n_findings = len(result.findings)
    console.print(
        f"\n[dim]Scan complete · {n_findings} finding{'s' if n_findings != 1 else ''}"
        f" · {elapsed:.1f}s · {report_path}[/dim]"
    )
    if _hub_emit:
        _hub_emit("scan.completed", {
            "target": result.target,
            "transport": result.transport,
            "duration_seconds": round(elapsed, 2),
            "findings_total": n_findings,
            "severity_counts": result.finding_count,
            "modules_run": result.modules_run,
        }, source_tool="corvus")

    if write_sarif:
        sarif_path = gen.write_sarif(result)
        console.print(f"SARIF  : {sarif_path}")

    if fail_on:
        try:
            threshold = Severity(fail_on)
        except ValueError:
            console.print(f"[red]Invalid severity: {fail_on}[/red]")
            raise typer.Exit(1)
        tidx = _SEVERITY_ORDER.index(threshold)
        if any(_SEVERITY_ORDER.index(f.severity) <= tidx for f in result.findings):
            raise typer.Exit(1)


def _resolve_modules(
    module_filter: str | list[str],
    registry: dict[str, type],
) -> list[str] | None:
    """Resolve a module filter to an ordered list of names, or None on error."""
    # Config-provided list of specific names
    if isinstance(module_filter, list):
        names: list[str] = []
        for m in module_filter:
            if m in registry:
                names.append(m)
            else:
                console.print(f"[red]Unknown module: {m}[/red]")
                console.print(f"Available: {', '.join(registry)}")
                return None
        return names

    # String selectors
    if module_filter == "all":
        return list(registry.keys())
    if module_filter == "static":
        return [n for n in registry if n in _STATIC or getattr(registry[n](), "is_static", False)]
    if module_filter == "dynamic":
        return [n for n in registry if n in _DYNAMIC or not getattr(registry[n](), "is_static", True)]
    if module_filter in registry:
        return [module_filter]

    console.print(f"[red]Unknown module: {module_filter}[/red]")
    console.print(f"Available: {', '.join(registry)}")
    return None


def _print_summary(result) -> None:
    table = Table(title="Summary", show_header=True)
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev, count in result.finding_count.items():
        color = _SEV_COLOR.get(sev, "white")
        table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count))
    console.print(table)


@app.command()
def batch(
    config: Annotated[Optional[Path], typer.Argument(
        help="Path to targets YAML file (optional when --stdio/--http are used)")] = None,
    stdio: Annotated[Optional[List[str]], typer.Option(
        "--stdio", help='Add stdio target inline: "npx @pkg/server" (repeatable)')] = None,
    http: Annotated[Optional[List[str]], typer.Option(
        "--http", help='Add HTTP target inline: "http://localhost:3000/mcp" (repeatable)')] = None,
    concurrency: Annotated[int, typer.Option(
        "--concurrency", "-j", help="Max concurrent scans (default: 5)")] = 5,
    output_dir: Annotated[Optional[Path], typer.Option("--output-dir", "-o")] = None,
    fail_on: Annotated[Optional[str], typer.Option(
        "--fail-on",
        help="Exit 1 if any target has findings at this severity or above")] = None,
    timeout: Annotated[Optional[int], typer.Option(
        "--timeout", help="Request timeout in seconds per MCP call")] = None,
    target_timeout: Annotated[Optional[int], typer.Option(
        "--target-timeout", help="Max seconds per target (default 600)")] = None,
    sarif: Annotated[bool, typer.Option("--sarif", help="Also write SARIF for each target")] = False,
    min_confidence: Annotated[Optional[int], typer.Option(
        "--min-confidence", help="Exclude findings below this confidence score (0-100)")] = None,
    module: Annotated[Optional[List[str]], typer.Option(
        "--module", "-m",
        help="all | static | dynamic | <module-name> (repeatable)")] = None,
):
    """Scan multiple MCP servers from a targets YAML file or inline --stdio/--http flags."""
    asyncio.run(_batch(config, stdio, http, concurrency, output_dir, fail_on, timeout, target_timeout, sarif, min_confidence, module))


async def _batch(
    config_path: Path | None,
    stdio_cmds: list[str] | None,
    http_urls: list[str] | None,
    concurrency: int,
    output_dir: Path | None,
    fail_on: str | None,
    timeout: int | None,
    target_timeout: int | None,
    sarif: bool,
    min_confidence: int | None,
    modules: list[str] | None = None,
) -> None:
    from .batch import load_batch_targets, run_batch

    # --- Resolve targets ---
    has_inline = bool(stdio_cmds or http_urls)
    if config_path and has_inline:
        console.print("[red]Use a YAML config file or --stdio/--http flags, not both.[/red]")
        raise typer.Exit(1)
    if not config_path and not has_inline:
        console.print("[red]Provide a targets YAML file or at least one --stdio/--http target.[/red]")
        raise typer.Exit(1)

    if config_path:
        try:
            targets = load_batch_targets(config_path)
        except FileNotFoundError:
            console.print(f"[red]File not found: {config_path}[/red]")
            raise typer.Exit(1)
        except ValueError as e:
            console.print(f"[red]Error loading batch config: {e}[/red]")
            raise typer.Exit(1)
    else:
        targets = _build_inline_targets(stdio_cmds or [], http_urls or [])

    if not targets:
        console.print("[yellow]No targets to scan.[/yellow]")
        raise typer.Exit(0)

    import datetime
    if output_dir is None:
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        output_dir = Path("corvus-sessions") / f"batch-{ts}"
    output_dir.mkdir(parents=True, exist_ok=True)

    _print_banner()
    panel_lines = [
        f"[bold]Targets[/bold]     {len(targets)}",
        f"[bold]Output[/bold]      {output_dir}",
        f"[bold]Concurrency[/bold] {concurrency}",
    ]
    console.print(Panel("\n".join(panel_lines), title="Batch Scan", border_style="dim", padding=(0, 1)))
    console.print()

    # S4: Rich live progress in TTY; plain run otherwise
    if console.is_terminal:
        result = await _run_batch_with_progress(
            targets, output_dir,
            timeout=timeout or 30,
            target_timeout=target_timeout or 600,
            min_confidence=min_confidence,
            sarif=sarif,
            modules=modules,
            concurrency=concurrency,
        )
    else:
        result = await run_batch(
            targets, output_dir,
            timeout=timeout or 30,
            target_timeout=target_timeout or 600,
            min_confidence=min_confidence,
            sarif=sarif,
            modules=modules,
            concurrency=concurrency,
        )

    summary_path = output_dir / "summary.md"
    summary_path.write_text(result.summary_md())

    console.print(result.summary_md())
    console.print(f"\nSummary: {summary_path}")
    if sarif:
        combined_path = output_dir / "combined.sarif"
        if combined_path.exists():
            console.print(f"SARIF   : {combined_path}")

    if fail_on:
        try:
            threshold = Severity(fail_on)
        except ValueError:
            console.print(f"[red]Invalid severity: {fail_on}[/red]")
            raise typer.Exit(1)
        tidx = _SEVERITY_ORDER.index(threshold)
        for t in result.targets:
            fc = t["finding_count"]
            for sev_str, count in fc.items():
                try:
                    sev = Severity(sev_str)
                    if count > 0 and _SEVERITY_ORDER.index(sev) <= tidx:
                        raise typer.Exit(1)
                except ValueError:
                    pass


@app.command("list-modules")
def list_modules(
    plugin_dir: Annotated[Optional[list[str]], typer.Option(
        "--plugin-dir", help="Also list plugins from this directory")] = None,
):
    """List available scan modules (built-ins + any discovered plugins)."""
    plugins = discover_plugins(plugin_dirs=plugin_dir or None)
    combined = {**_ALL_MODULES, **plugins}
    _print_banner()
    table = Table(title="Modules")
    table.add_column("Name")
    table.add_column("OWASP")
    table.add_column("Type")
    table.add_column("Source")
    table.add_column("Description")
    for name, cls in combined.items():
        m = cls()
        source = "plugin" if name in plugins else "built-in"
        table.add_row(
            name, m.owasp_id, "static" if m.is_static else "dynamic", source, m.description
        )
    console.print(table)


@app.command()
def diff(
    old: Annotated[Path, typer.Argument(help="Baseline SARIF report (older scan)")],
    new: Annotated[Path, typer.Argument(help="Comparison SARIF report (newer scan)")],
    json_output: Annotated[bool, typer.Option("--json", help="Output diff as JSON")] = False,
) -> None:
    """Compare two SARIF reports — show new and fixed findings."""
    import json as _json
    from .diff import diff_sarifs, _severity_from_level

    for p, label in [(old, "old"), (new, "new")]:
        if not p.exists():
            console.print(f"[red]File not found ({label}): {p}[/red]")
            raise typer.Exit(1)

    result = diff_sarifs(old, new)

    if json_output:
        console.print(_json.dumps(
            {"new": result.new, "fixed": result.fixed, "unchanged_count": result.unchanged_count},
            indent=2,
        ))
        return

    console.print(f"\n[bold]SARIF Diff[/bold]  {old.name} → {new.name}")
    console.print(
        f"  [green]+{len(result.new)} new[/green]  "
        f"[red]-{len(result.fixed)} fixed[/red]  "
        f"{result.unchanged_count} unchanged\n"
    )

    for label, findings, color in [("NEW", result.new, "green"), ("FIXED", result.fixed, "red")]:
        if findings:
            console.print(f"[bold {color}]{label} findings:[/bold {color}]")
            for r in findings:
                sev = _severity_from_level(r.get("level"))
                msg = r.get("message", {}).get("text", "")[:80]
                c = _SEV_COLOR.get(sev.lower(), "white")
                console.print(f"  [{c}][{sev}][/{c}] {r.get('ruleId', '')} — {msg}")
            console.print()

    if not result.new and not result.fixed:
        console.print("[green]No changes — reports are identical.[/green]")


@app.command()
def score(
    report: Annotated[Path, typer.Argument(help="Path to report.json from a corvus scan")],
    json_output: Annotated[bool, typer.Option("--json", help="Output score as JSON")] = False,
) -> None:
    """Compute Risk Score (0–100) from scan findings."""
    import json as _json
    from .core.models import ScanResult
    from .scoring import compute_risk_score, risk_tier

    if not report.exists():
        console.print(f"[red]File not found: {report}[/red]")
        raise typer.Exit(1)

    try:
        data = _json.loads(report.read_text(encoding="utf-8"))
        result = ScanResult.model_validate(data)
    except Exception as exc:
        console.print(f"[red]Failed to parse report: {exc}[/red]")
        raise typer.Exit(1)

    sc = compute_risk_score(result.findings)
    tier = risk_tier(sc)
    counts = result.finding_count

    if json_output:
        out = {
            "score": sc,
            "tier": tier,
            "target": result.target,
            "findings": counts,
        }
        console.print(_json.dumps(out, indent=2))
        return

    tier_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "CLEAR": "green"}
    color = tier_color.get(tier, "white")
    console.print(f"\n[bold]Risk Score[/bold]  [{color}]{sc}/100 — {tier}[/{color}]")
    console.print(f"Target      : {result.target}")
    console.print()

    table = Table(title="Finding Breakdown", show_header=True)
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev, count in counts.items():
        c = _SEV_COLOR.get(sev, "white")
        table.add_row(f"[{c}]{sev.upper()}[/{c}]", str(count))
    console.print(table)


@app.command()
def init(
    output: Annotated[Optional[Path], typer.Option(
        "--output", "-o", help="Output path (default: corvus.toml)")] = None,
) -> None:
    """Generate a corvus.toml skeleton with all available options."""
    dest = output or Path("corvus.toml")
    if dest.exists():
        console.print(f"[yellow]File already exists: {dest}[/yellow]")
        raise typer.Exit(1)

    skeleton = """\
# Corvus configuration — generated by `corvus init`
# Docs: https://github.com/CobaltoSec/corvus

[scan]
# Transport: stdio | http
transport = "stdio"

# stdio: command to launch the MCP server
# cmd = "npx @modelcontextprotocol/server-everything"

# http: URL of the MCP server
# url = "http://localhost:3000/mcp"

# Modules: all | static | dynamic | list of module names
modules = "all"

# Output directory (default: corvus-sessions/scan-<timestamp>)
# output_dir = "results"

# Request timeout in seconds
timeout = 30

# Also write SARIF 2.1.0 output
sarif = false

# Exit 1 if findings reach this severity: critical | high | medium | low
# fail_on = "high"

# Exclude findings below this confidence (0-100)
# min_confidence = 50

# Seconds to wait between probes (rate limiting / WAF bypass)
# delay = 0.0

# Extra env vars for the MCP subprocess (stdio only)
# [scan.env]
# MCP_API_KEY = "secret"
# NODE_ENV = "production"

# HTTP headers (http transport only)
# [scan.headers]
# Authorization = "Bearer <token>"
# X-Api-Version = "2"

# External plugin directories
# plugin_dirs = ["/path/to/my/plugins"]
"""
    dest.write_text(skeleton, encoding="utf-8")
    console.print(f"[green]Created:[/green] {dest}")


@app.command()
def report(
    report_json: Annotated[Path, typer.Argument(help="Path to report.json from a corvus scan")],
    fmt: Annotated[str, typer.Option(
        "--format", help="Output format: md | sarif | html | all (default: all)")] = "all",
    output_dir: Annotated[Optional[Path], typer.Option("--output-dir", "-o")] = None,
) -> None:
    """Regenerate MD, SARIF, or HTML report from an existing report.json without re-scanning."""
    import json as _json
    from .core.models import ScanResult

    if not report_json.exists():
        console.print(f"[red]File not found: {report_json}[/red]")
        raise typer.Exit(1)

    try:
        data = _json.loads(report_json.read_text(encoding="utf-8"))
        result = ScanResult.model_validate(data)
    except Exception as exc:
        console.print(f"[red]Failed to parse report.json: {exc}[/red]")
        raise typer.Exit(1)

    dest = output_dir or report_json.parent
    gen = ReportGenerator(dest)

    valid_formats = {"md", "sarif", "html", "all"}
    if fmt not in valid_formats:
        console.print(f"[red]Unknown format: {fmt}. Choose from: {', '.join(sorted(valid_formats))}[/red]")
        raise typer.Exit(1)

    if fmt in ("md", "all"):
        p = gen.write_md(result)
        console.print(f"MD     : {p}")
    if fmt in ("sarif", "all"):
        p = gen.write_sarif(result)
        console.print(f"SARIF  : {p}")
    if fmt in ("html", "all"):
        p = gen.write_html(result)
        console.print(f"HTML   : {p}")


@app.command()
def history(
    limit: Annotated[int, typer.Option("--limit", "-n", help="Max rows to show")] = 50,
    case_study: Annotated[Optional[str], typer.Option("--cs", help="Filter by case study (e.g. CS07)")] = None,
    pkg: Annotated[Optional[str], typer.Option("--pkg", help="Filter by package name substring")] = None,
    stats: Annotated[bool, typer.Option("--stats", help="Show aggregate stats only")] = False,
) -> None:
    """Show scan history from ~/.corvus/history.db."""
    from .history import aggregate_stats, list_scans

    if stats:
        agg = aggregate_stats()
        if not agg:
            console.print("[yellow]No history yet.[/yellow]")
            return
        t = Table(show_header=False, box=None, padding=(0, 2))
        for k, v in agg.items():
            if k == "error_breakdown":
                continue
            t.add_row(f"[dim]{k}[/dim]", str(v))
        console.print(t)
        if agg.get("error_breakdown"):
            console.print("\n[bold]Error categories:[/bold]")
            for cat, cnt in agg["error_breakdown"].items():
                console.print(f"  {cat}: {cnt}")
        return

    rows = list_scans(limit=limit, case_study=case_study, pkg_filter=pkg)
    if not rows:
        console.print("[yellow]No history yet.[/yellow]")
        return

    t = Table(show_header=True)
    t.add_column("ID",    style="dim", width=5)
    t.add_column("Date",  width=12)
    t.add_column("Package", min_width=30)
    t.add_column("Status", width=10)
    t.add_column("Raw", justify="right", width=5)
    t.add_column("CS",   width=6)
    t.add_column("Ver",  width=8)

    STATUS_STYLE = {"ok": "green", "error": "red", "skip": "yellow"}
    for r in rows:
        date = r["scan_date"][:10]
        status = r["status"]
        cat = r.get("error_category") or ""
        status_label = f"{status}({cat})" if cat else status
        t.add_row(
            str(r["id"]),
            date,
            r["pkg_name"],
            f"[{STATUS_STYLE.get(status, 'white')}]{status_label}[/]",
            str(r["raw_count"]),
            r.get("case_study") or "",
            r.get("corvus_version") or "",
        )
    console.print(t)


@app.command()
def version():
    """Print version."""
    console.print(f"corvus {__version__}")

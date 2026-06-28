from __future__ import annotations

import asyncio
import datetime
import shlex
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import CorvusConfig, load_config
from .core.models import Severity
from .core.session import ScanSession
from .discovery.enumerator import MCPEnumerator
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
from .modules.static.auth_audit import AuthAuditModule
from .modules.static.log_audit import LogAuditModule
from .modules.static.schema_audit import SchemaAuditModule
from .modules.static.scope_audit import ScopeAuditModule
from .modules.static.shadow_tool import ShadowToolModule
from .modules.static.supply_chain import SupplyChainModule
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
    "supply-chain":    SupplyChainModule,
    "tool-poisoning":  ToolPoisoningModule,
    "schema-audit":    SchemaAuditModule,
    "shadow-tool":     ShadowToolModule,
    "auth-audit":      AuthAuditModule,
    "log-audit":       LogAuditModule,
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
    "output-encoding": OutputEncodingModule,
}
_STATIC  = {"scope-audit", "supply-chain", "tool-poisoning", "schema-audit", "shadow-tool", "auth-audit", "log-audit"}
_DYNAMIC = {
    "cmd-injection", "token-exposure", "schema-bypass", "response-flood", "rug-pull",
    "ssrf", "endpoint-probe", "param-smuggling", "init-audit", "proto-fuzz", "output-encoding",
}

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEV_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "blue",
    "info":     "dim",
}


@app.command()
def scan(
    transport: Annotated[Optional[str], typer.Option(
        "--transport", "-t", help="stdio | http (overrides config)")] = None,
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
):
    """Scan an MCP server for security vulnerabilities."""
    asyncio.run(_scan(
        transport, cmd, url, module, output_dir, fail_on, timeout,
        sarif, log_requests, header, config_file, plugin_dir, min_confidence,
    ))


async def _scan(
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
) -> None:
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

    # --- Merge: CLI overrides config; config fills what CLI omits ---
    transport_name = cli_transport or cfg.scan.transport
    cmd            = cli_cmd or cfg.scan.cmd
    url            = cli_url or cfg.scan.url
    timeout        = cli_timeout if cli_timeout is not None else cfg.scan.timeout
    fail_on        = cli_fail_on or cfg.scan.fail_on
    write_sarif    = cli_sarif or cfg.scan.sarif
    output_dir_str = str(output_dir) if output_dir else cfg.scan.output_dir

    # Modules: CLI string takes full precedence; config can be str or list
    if cli_module:
        module_filter: str | list[str] = cli_module
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

    console.print(f"\n[bold cyan]Corvus v{__version__}[/bold cyan]  MCP Security Scanner")
    console.print(f"Target     : {target}")
    console.print(f"Transport  : {transport_name}")
    console.print(f"Modules    : {', '.join(names)}")
    if config_file:
        console.print(f"Config     : {config_file}")
    console.print()

    async with xport:
        console.print("[bold]Enumerating surface...[/bold]")
        surface = await MCPEnumerator(xport).enumerate()
        console.print(f"  Tools      : {len(surface.tools)}")
        console.print(f"  Resources  : {len(surface.resources)}")
        console.print(f"  Prompts    : {len(surface.prompts)}")
        if surface.server_name:
            console.print(f"  Server     : {surface.server_name} {surface.server_version}")
        console.print()

        for name in names:
            mod = modules_registry[name]()
            label = "static" if mod.is_static else "dynamic"
            console.print(f"[bold yellow][{mod.owasp_id}][/bold yellow] {mod.category} ({label})")
            findings = await mod.run(surface, xport, session)
            for f in findings:
                session.add_finding(f)
            if findings:
                for f in findings:
                    color = _SEV_COLOR.get(f.severity.value, "white")
                    console.print(f"  [{color}][{f.severity.value.upper()}][/{color}] {f.title}")
            else:
                console.print("  [green]No findings[/green]")
            console.print()

    if min_confidence is not None:
        session.findings = [f for f in session.findings if f.confidence >= min_confidence]

    result = session.to_result(
        surface, names,
        exchanges=list(xport.exchanges) if cli_log_requests else [],
    )
    gen = ReportGenerator(resolved_output_dir)
    report_path = gen.write(result)

    _print_summary(result)
    console.print(f"\nReport: {report_path}")

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
    config: Annotated[Path, typer.Argument(help="Path to targets YAML file")],
    output_dir: Annotated[Optional[Path], typer.Option("--output-dir", "-o")] = None,
    fail_on: Annotated[Optional[str], typer.Option(
        "--fail-on",
        help="Exit 1 if any target has findings at this severity or above")] = None,
    timeout: Annotated[Optional[int], typer.Option(
        "--timeout", help="Request timeout in seconds per target")] = None,
    sarif: Annotated[bool, typer.Option("--sarif", help="Also write SARIF for each target")] = False,
    min_confidence: Annotated[Optional[int], typer.Option(
        "--min-confidence", help="Exclude findings below this confidence score (0-100)")] = None,
):
    """Scan multiple MCP servers from a targets YAML file."""
    asyncio.run(_batch(config, output_dir, fail_on, timeout, sarif, min_confidence))


async def _batch(
    config_path: Path,
    output_dir: Path | None,
    fail_on: str | None,
    timeout: int | None,
    sarif: bool,
    min_confidence: int | None,
) -> None:
    from .batch import load_batch_targets, run_batch

    try:
        targets = load_batch_targets(config_path)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]Error loading batch config: {e}[/red]")
        raise typer.Exit(1)

    import datetime
    if output_dir is None:
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        output_dir = Path("corvus-sessions") / f"batch-{ts}"
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"\n[bold cyan]Corvus Batch Scan[/bold cyan]  {len(targets)} target(s)")
    console.print(f"Output dir : {output_dir}\n")

    result = await run_batch(
        targets,
        output_dir,
        timeout=timeout or 30,
        min_confidence=min_confidence,
        sarif=sarif,
    )

    summary_path = output_dir / "summary.md"
    summary_path.write_text(result.summary_md())

    console.print(result.summary_md())
    console.print(f"\nSummary: {summary_path}")

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
def version():
    """Print version."""
    console.print(f"corvus {__version__}")

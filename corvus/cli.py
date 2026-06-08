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
from .core.models import Severity
from .core.session import ScanSession
from .discovery.enumerator import MCPEnumerator
from .modules.dynamic.info_disclosure import InfoDisclosureModule
from .modules.dynamic.param_injection import ParamInjectionModule
from .modules.dynamic.response_flood import ResponseFloodModule
from .modules.dynamic.rug_pull import RugPullModule
from .modules.dynamic.schema_bypass import SchemaBypassModule
from .modules.static.auth_audit import AuthAuditModule
from .modules.static.schema_audit import SchemaAuditModule
from .modules.static.shadow_tool import ShadowToolModule
from .modules.static.tool_poisoning import ToolPoisoningModule
from .reporting.report import ReportGenerator
from .transport.http import HttpTransport
from .transport.stdio import StdioTransport

app = typer.Typer(name="corvus", help="MCP server security testing framework", add_completion=False)
console = Console()

_ALL_MODULES = {
    "tool-poisoning": ToolPoisoningModule,
    "schema-audit":   SchemaAuditModule,
    "shadow-tool":    ShadowToolModule,
    "auth-audit":     AuthAuditModule,
    "param-injection": ParamInjectionModule,
    "info-disclosure": InfoDisclosureModule,
    "schema-bypass":   SchemaBypassModule,
    "response-flood":  ResponseFloodModule,
    "rug-pull":        RugPullModule,
}
_STATIC = {"tool-poisoning", "schema-audit", "shadow-tool", "auth-audit"}
_DYNAMIC = {"param-injection", "info-disclosure", "schema-bypass", "response-flood", "rug-pull"}

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
    transport: Annotated[str, typer.Option("--transport", "-t", help="stdio | http")] = "stdio",
    cmd: Annotated[Optional[str], typer.Option("--cmd", help="Command to launch MCP server (stdio)")] = None,
    url: Annotated[Optional[str], typer.Option("--url", help="URL of MCP server (http)")] = None,
    module: Annotated[str, typer.Option("--module", "-m",
        help="all | static | dynamic | <module-name>")] = "all",
    output_dir: Annotated[Optional[Path], typer.Option("--output-dir", "-o")] = None,
    fail_on: Annotated[Optional[str], typer.Option("--fail-on",
        help="Exit 1 if any findings at this severity or above (critical|high|medium|low)")] = None,
    timeout: Annotated[int, typer.Option("--timeout")] = 30,
):
    """Scan an MCP server for security vulnerabilities."""
    asyncio.run(_scan(transport, cmd, url, module, output_dir, fail_on, timeout))


async def _scan(
    transport_name: str,
    cmd: str | None,
    url: str | None,
    module_filter: str,
    output_dir: Path | None,
    fail_on: str | None,
    timeout: int,
) -> None:
    if output_dir is None:
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        output_dir = Path("corvus-sessions") / f"scan-{ts}"

    # Build transport
    if transport_name == "stdio":
        if not cmd:
            console.print("[red]--cmd is required for stdio transport[/red]")
            raise typer.Exit(1)
        xport = StdioTransport(shlex.split(cmd, posix=(sys.platform != "win32")), timeout=timeout)
        target = cmd
    elif transport_name == "http":
        if not url:
            console.print("[red]--url is required for http transport[/red]")
            raise typer.Exit(1)
        xport = HttpTransport(url, timeout=timeout)
        target = url
    else:
        console.print(f"[red]Unknown transport: {transport_name}[/red]")
        raise typer.Exit(1)

    # Resolve modules
    if module_filter == "all":
        names = list(_ALL_MODULES.keys())
    elif module_filter == "static":
        names = list(_STATIC)
    elif module_filter == "dynamic":
        names = list(_DYNAMIC)
    elif module_filter in _ALL_MODULES:
        names = [module_filter]
    else:
        console.print(f"[red]Unknown module: {module_filter}[/red]")
        console.print(f"Available: {', '.join(_ALL_MODULES)}")
        raise typer.Exit(1)

    session = ScanSession(target=target, transport=transport_name, output_dir=output_dir)

    console.print(f"\n[bold cyan]Corvus v{__version__}[/bold cyan]  MCP Security Scanner")
    console.print(f"Target     : {target}")
    console.print(f"Transport  : {transport_name}")
    console.print(f"Modules    : {', '.join(names)}")
    console.print()

    async with xport:
        console.print("[bold]Enumerating surface...[/bold]")
        enumerator = MCPEnumerator(xport)
        surface = await enumerator.enumerate()
        console.print(f"  Tools      : {len(surface.tools)}")
        console.print(f"  Resources  : {len(surface.resources)}")
        console.print(f"  Prompts    : {len(surface.prompts)}")
        if surface.server_name:
            console.print(f"  Server     : {surface.server_name} {surface.server_version}")
        console.print()

        for name in names:
            mod = _ALL_MODULES[name]()
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

    result = session.to_result(surface, names)
    gen = ReportGenerator(output_dir)
    report_path = gen.write(result)

    _print_summary(result)
    console.print(f"\nReport: {report_path}")

    if fail_on:
        try:
            threshold = Severity(fail_on)
        except ValueError:
            console.print(f"[red]Invalid severity: {fail_on}[/red]")
            raise typer.Exit(1)
        tidx = _SEVERITY_ORDER.index(threshold)
        if any(_SEVERITY_ORDER.index(f.severity) <= tidx for f in result.findings):
            raise typer.Exit(1)


def _print_summary(result) -> None:
    table = Table(title="Summary", show_header=True)
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev, count in result.finding_count.items():
        color = _SEV_COLOR.get(sev, "white")
        table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count))
    console.print(table)


@app.command("list-modules")
def list_modules():
    """List available scan modules."""
    table = Table(title="Modules")
    table.add_column("Name")
    table.add_column("OWASP")
    table.add_column("Type")
    table.add_column("Description")
    for name, cls in _ALL_MODULES.items():
        m = cls()
        table.add_row(name, m.owasp_id, "static" if m.is_static else "dynamic", m.description)
    console.print(table)


@app.command()
def version():
    """Print version."""
    console.print(f"corvus {__version__}")

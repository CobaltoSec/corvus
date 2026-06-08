"""Tests for the Corvus plugin discovery system."""
from __future__ import annotations

from pathlib import Path

import pytest

from corvus.modules.base import ScanModule
from corvus.plugins import _load_file_plugins, discover_plugins

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Basic discovery
# ---------------------------------------------------------------------------

def test_discover_from_directory() -> None:
    plugins = discover_plugins(plugin_dirs=[FIXTURES], use_entry_points=False)
    assert "custom-sample" in plugins


def test_loaded_plugin_is_scan_module_subclass() -> None:
    plugins = discover_plugins(plugin_dirs=[FIXTURES], use_entry_points=False)
    cls = plugins["custom-sample"]
    assert issubclass(cls, ScanModule)


def test_plugin_has_required_attributes() -> None:
    plugins = discover_plugins(plugin_dirs=[FIXTURES], use_entry_points=False)
    instance = plugins["custom-sample"]()
    assert instance.owasp_id
    assert instance.name == "custom-sample"
    assert instance.description
    assert isinstance(instance.is_static, bool)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_nonexistent_dir_is_skipped() -> None:
    plugins = discover_plugins(plugin_dirs=["/does/not/exist"], use_entry_points=False)
    assert plugins == {}


def test_empty_dir_yields_no_plugins(tmp_path: Path) -> None:
    plugins = discover_plugins(plugin_dirs=[tmp_path], use_entry_points=False)
    assert plugins == {}


def test_malformed_plugin_is_silently_skipped(tmp_path: Path) -> None:
    bad = tmp_path / "bad_plugin.py"
    bad.write_text("raise RuntimeError('intentional load failure')", encoding="utf-8")
    plugins = discover_plugins(plugin_dirs=[tmp_path], use_entry_points=False)
    assert plugins == {}


def test_plain_py_file_without_scan_module_is_ignored(tmp_path: Path) -> None:
    """A .py file that defines no ScanModule subclass contributes nothing."""
    harmless = tmp_path / "helper.py"
    harmless.write_text("MY_CONSTANT = 42\ndef helper(): pass\n", encoding="utf-8")
    plugins = discover_plugins(plugin_dirs=[tmp_path], use_entry_points=False)
    assert plugins == {}


def test_multiple_dirs_merged() -> None:
    """Plugins from multiple directories should all appear in the result."""
    import tempfile

    with tempfile.TemporaryDirectory() as d2:
        extra = Path(d2) / "extra_plugin.py"
        extra.write_text(
            """
from corvus.modules.base import ScanModule
from corvus.core.models import Finding, MCPSurface, OWASPCategory, Severity
from corvus.core.session import ScanSession
from corvus.transport.base import MCPTransport

class ExtraModule(ScanModule):
    owasp_id = "MCP09"
    category = "Extra"
    name = "extra-plugin"
    description = "Extra plugin for multi-dir test"
    is_static = True

    async def run(self, surface, transport, session):
        return []
""",
            encoding="utf-8",
        )
        plugins = discover_plugins(plugin_dirs=[FIXTURES, d2], use_entry_points=False)
        assert "custom-sample" in plugins
        assert "extra-plugin" in plugins


def test_entry_points_discovery_does_not_crash() -> None:
    """Should not raise even when no corvus.modules entry points are registered."""
    plugins = discover_plugins(plugin_dirs=None, use_entry_points=True)
    assert isinstance(plugins, dict)


# ---------------------------------------------------------------------------
# Runtime execution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_plugin_run_returns_findings() -> None:
    from corvus.core.models import MCPSurface
    from corvus.core.session import ScanSession

    plugins = discover_plugins(plugin_dirs=[FIXTURES], use_entry_points=False)
    instance = plugins["custom-sample"]()
    surface = MCPSurface(server_name="test")
    session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
    findings = await instance.run(surface, None, session)  # static module: transport unused
    assert len(findings) == 1
    assert findings[0].title == "Custom plugin executed successfully"


@pytest.mark.asyncio
async def test_plugin_integrated_in_scan_session(tmp_path: Path) -> None:
    """End-to-end: discover plugin, merge with built-in modules, run it."""
    from corvus.core.models import MCPSurface
    from corvus.core.session import ScanSession
    from corvus.cli import _ALL_MODULES

    plugins = discover_plugins(plugin_dirs=[FIXTURES], use_entry_points=False)
    combined = {**_ALL_MODULES, **plugins}  # plugins override built-ins by name
    assert "custom-sample" in combined

    cls = combined["custom-sample"]
    instance = cls()
    surface = MCPSurface(server_name="test")
    session = ScanSession("test", "stdio", tmp_path)
    findings = await instance.run(surface, None, session)
    assert findings

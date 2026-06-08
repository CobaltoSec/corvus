"""Tests for corvus.toml config loading and validation."""
from __future__ import annotations

from pathlib import Path

import pytest

from corvus.config import CorvusConfig, ScanConfig, load_config

FIXTURES = Path(__file__).parent / "fixtures"


def test_load_valid_config() -> None:
    cfg = load_config(FIXTURES / "sample_config.toml")
    assert cfg.scan.transport == "stdio"
    assert cfg.scan.timeout == 15
    assert cfg.scan.sarif is True


def test_modules_loaded_as_list() -> None:
    cfg = load_config(FIXTURES / "sample_config.toml")
    assert isinstance(cfg.scan.modules, list)
    assert "tool-poisoning" in cfg.scan.modules
    assert "schema-audit" in cfg.scan.modules


def test_headers_loaded() -> None:
    cfg = load_config(FIXTURES / "sample_config.toml")
    assert cfg.scan.headers.get("X-Custom-Header") == "test-value"
    assert cfg.scan.headers.get("X-Api-Version") == "2"


def test_default_config_sensible_defaults() -> None:
    cfg = CorvusConfig()
    assert cfg.scan.transport == "stdio"
    assert cfg.scan.modules == "all"
    assert cfg.scan.timeout == 30
    assert cfg.scan.sarif is False
    assert cfg.scan.headers == {}
    assert cfg.scan.plugin_dirs == []
    assert cfg.scan.cmd is None
    assert cfg.scan.url is None
    assert cfg.scan.fail_on is None


def test_missing_config_raises_file_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        load_config(Path("does-not-exist.toml"))


def test_modules_as_string_is_valid() -> None:
    cfg = CorvusConfig.model_validate({"scan": {"modules": "static"}})
    assert cfg.scan.modules == "static"


def test_cli_override_via_model_copy() -> None:
    """Simulate CLI override: model_copy(update={...}) mirrors merge logic in cli._scan."""
    cfg = load_config(FIXTURES / "sample_config.toml")
    # User passes --timeout 60 and --transport http on the CLI
    merged = cfg.scan.model_copy(update={"timeout": 60, "transport": "http"})
    assert merged.timeout == 60
    assert merged.transport == "http"
    # Other fields remain from the config file
    assert merged.sarif is True
    assert merged.headers.get("X-Custom-Header") == "test-value"


def test_scan_config_partial_toml() -> None:
    """A toml with only some fields should fill the rest with defaults."""
    cfg = CorvusConfig.model_validate({"scan": {"timeout": 5}})
    assert cfg.scan.timeout == 5
    assert cfg.scan.transport == "stdio"
    assert cfg.scan.modules == "all"


def test_empty_toml_yields_all_defaults(tmp_path: Path) -> None:
    empty = tmp_path / "empty.toml"
    empty.write_text("", encoding="utf-8")
    cfg = load_config(empty)
    assert cfg.scan.transport == "stdio"
    assert cfg.scan.modules == "all"

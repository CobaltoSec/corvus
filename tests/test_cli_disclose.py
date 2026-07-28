"""Tests for corvus disclose CLI command."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from corvus.cli import app

runner = CliRunner()


def test_disclose_dry_run():
    result = runner.invoke(app, ["disclose", "GHSA-test-xxxx", "--dry-run"])
    assert result.exit_code == 0
    assert "dry-run" in result.output


def test_disclose_no_ibis():
    with patch("pathlib.Path.exists", return_value=False):
        result = runner.invoke(app, ["disclose", "GHSA-test-xxxx"])
    assert result.exit_code != 0

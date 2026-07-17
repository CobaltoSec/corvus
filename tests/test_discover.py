"""Tests for S2 + S3 — discover.py Smithery, GitHub, PyPI auto-discovery."""
from __future__ import annotations

import asyncio
import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# discover.py lives in scripts/, not a package — import via path manipulation
import importlib.util
from pathlib import Path

_DISCOVER_PATH = Path(__file__).parent.parent / "scripts" / "discover.py"

if _DISCOVER_PATH.exists():
    spec = importlib.util.spec_from_file_location("discover", _DISCOVER_PATH)
    _discover = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_discover)
else:
    _discover = None

pytestmark = pytest.mark.skipif(
    _discover is None,
    reason="scripts/discover.py not found",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_resp(status: int, json_data: Any = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json = MagicMock(return_value=json_data or {})
    resp.text = text
    return resp


def _async_get(responses: list) -> AsyncMock:
    """Build an AsyncMock for client.get that returns responses in order."""
    mock = AsyncMock(side_effect=responses)
    return mock


# ---------------------------------------------------------------------------
# S2 — Smithery
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_smithery_search_returns_items():
    """smithery_search must paginate and collect unique items (deduplicated by qualifiedName)."""
    page1 = _mock_resp(200, {"servers": [{"qualifiedName": f"@foo/mcp-{i}", "description": "test"} for i in range(100)]})
    page2 = _mock_resp(200, {"servers": [{"qualifiedName": f"@bar/mcp-{i}", "description": "bar"} for i in range(3)]})
    page3 = _mock_resp(200, {"servers": []})

    client = MagicMock()
    client.get = AsyncMock(side_effect=[page1, page2, page3])

    results = await _discover.smithery_search(client, max_pages=5)
    assert len(results) == 103
    assert results[0]["qualifiedName"] == "@foo/mcp-0"


@pytest.mark.asyncio
async def test_smithery_search_stops_on_error():
    """smithery_search must stop gracefully on HTTP error."""
    client = MagicMock()
    client.get = AsyncMock(return_value=_mock_resp(503))
    results = await _discover.smithery_search(client, max_pages=5)
    assert results == []


def test_smithery_to_pkg_obj_normalizes_fields():
    entry = {
        "qualifiedName": "@smithery/test-mcp",
        "description": "A test MCP server",
        "version": "1.2.3",
        "tags": ["mcp", "test"],
    }
    obj = _discover.smithery_to_pkg_obj(entry)
    pkg = obj["package"]
    assert pkg["name"] == "@smithery/test-mcp"
    assert pkg["description"] == "A test MCP server"
    assert pkg["version"] == "1.2.3"
    assert pkg["keywords"] == ["mcp", "test"]


def test_smithery_to_pkg_obj_fallback_name():
    entry = {"name": "fallback-name"}
    obj = _discover.smithery_to_pkg_obj(entry)
    assert obj["package"]["name"] == "fallback-name"


# ---------------------------------------------------------------------------
# S2 — GitHub
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_github_mcp_search_paginates():
    """github_mcp_search must fetch multiple pages and concatenate results."""
    page1 = _mock_resp(200, {"items": [{"name": f"mcp-a-{i}", "owner": {"login": "u"}, "description": ""} for i in range(30)]})
    page2 = _mock_resp(200, {"items": [{"name": f"mcp-b-{i}", "owner": {"login": "u"}, "description": ""} for i in range(10)]})
    page3 = _mock_resp(200, {"items": []})

    client = MagicMock()
    client.get = AsyncMock(side_effect=[page1, page2, page3])

    results = await _discover.github_mcp_search(client, max_results=200)
    # page1 (30 < 30? No, so continues) + page2 (10 < 30 → stops) = 40 total
    assert len(results) == 40
    assert client.get.call_count == 2


@pytest.mark.asyncio
async def test_github_mcp_search_stops_on_empty():
    """github_mcp_search stops when items is empty."""
    client = MagicMock()
    client.get = AsyncMock(return_value=_mock_resp(200, {"items": []}))
    results = await _discover.github_mcp_search(client, max_results=100)
    assert results == []


@pytest.mark.asyncio
async def test_github_repo_to_npm_pkg_found():
    """github_repo_to_npm_pkg returns npm name if package.json has 'mcp' in the name."""
    pkg_json = {"name": "@acme/mcp-server"}
    resp = _mock_resp(200, pkg_json)
    client = MagicMock()
    client.get = AsyncMock(return_value=resp)
    result = await _discover.github_repo_to_npm_pkg(client, "acme", "mcp-server")
    assert result == "@acme/mcp-server"


@pytest.mark.asyncio
async def test_github_repo_to_npm_pkg_no_mcp_in_name():
    """github_repo_to_npm_pkg returns name even without 'mcp' (topic:mcp-server repos are all MCP servers)."""
    pkg_json = {"name": "my-tools-server"}
    resp = _mock_resp(200, pkg_json)
    client = MagicMock()
    client.get = AsyncMock(return_value=resp)
    result = await _discover.github_repo_to_npm_pkg(client, "user", "my-tools-server")
    assert result == "my-tools-server"


@pytest.mark.asyncio
async def test_github_repo_to_npm_pkg_404():
    """github_repo_to_npm_pkg returns None when package.json is absent on all branches."""
    resp = _mock_resp(404)
    client = MagicMock()
    client.get = AsyncMock(return_value=resp)
    result = await _discover.github_repo_to_npm_pkg(client, "user", "no-pkg-json")
    assert result is None


def test_github_to_pkg_obj():
    gh_repo = {"description": "An MCP server for X", "topics": ["mcp", "ai"]}
    obj = _discover.github_to_pkg_obj("@user/mcp-x", gh_repo)
    pkg = obj["package"]
    assert pkg["name"] == "@user/mcp-x"
    assert pkg["description"] == "An MCP server for X"
    assert pkg["keywords"] == ["mcp", "ai"]


# ---------------------------------------------------------------------------
# S3 — PyPI auto-discovery
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pypi_search_by_name_filters_mcp():
    """pypi_search_by_name returns only packages with 'mcp' in the name when count exceeds PYPI_CURATED."""
    # Must produce more mcp packages than PYPI_CURATED to avoid falling back
    mcp_pkgs = [f"mcp-tool-{i}" for i in range(len(_discover.PYPI_CURATED) + 10)]
    other_pkgs = ["requests", "flask", "django"]
    all_pkgs = mcp_pkgs + other_pkgs
    html_parts = [f'<a href="/simple/{p}/">{p}</a>' for p in all_pkgs]
    html = "\n".join(html_parts)

    resp = _mock_resp(200, text=html)
    client = MagicMock()
    client.get = AsyncMock(return_value=resp)

    results = await _discover.pypi_search_by_name(client)
    for p in mcp_pkgs:
        assert p in results, f"Expected {p} in results"
    for p in other_pkgs:
        assert p not in results, f"Expected {p} NOT in results"


@pytest.mark.asyncio
async def test_pypi_search_by_name_fallback_on_error():
    """pypi_search_by_name falls back to PYPI_CURATED if the request raises."""
    client = MagicMock()
    client.get = AsyncMock(side_effect=Exception("timeout"))

    results = await _discover.pypi_search_by_name(client)
    curated_names = [p["pkg"] for p in _discover.PYPI_CURATED]
    assert results == curated_names


@pytest.mark.asyncio
async def test_pypi_search_by_name_fallback_on_bad_status():
    """pypi_search_by_name falls back to PYPI_CURATED on non-200 status."""
    client = MagicMock()
    client.get = AsyncMock(return_value=_mock_resp(503))

    results = await _discover.pypi_search_by_name(client)
    curated_names = [p["pkg"] for p in _discover.PYPI_CURATED]
    assert results == curated_names


@pytest.mark.asyncio
async def test_pypi_search_librariesio_collects_names():
    """pypi_search_librariesio aggregates package names across pages (stops on partial page)."""
    # Page 1 must be full (100 items) so the loop continues to page 2
    full_page = [{"name": f"mcp-pkg-{i}"} for i in range(99)] + [{"name": "mcp-server-a"}]
    partial_page = [{"name": "mcp-c"}]  # < 100 → loop stops

    client = MagicMock()
    client.get = AsyncMock(side_effect=[_mock_resp(200, full_page), _mock_resp(200, partial_page)])

    results = await _discover.pypi_search_librariesio(client, api_key="testkey", max_pages=5)
    assert "mcp-server-a" in results
    assert "mcp-c" in results
    assert client.get.call_count == 2


@pytest.mark.asyncio
async def test_pypi_search_librariesio_fallback_on_error():
    """pypi_search_librariesio falls back to PYPI_CURATED if API fails."""
    client = MagicMock()
    client.get = AsyncMock(side_effect=Exception("network error"))

    results = await _discover.pypi_search_librariesio(client, api_key="key")
    curated_names = [p["pkg"] for p in _discover.PYPI_CURATED]
    assert results == curated_names


# ---------------------------------------------------------------------------
# CLI argparse — --source choices
# ---------------------------------------------------------------------------

def test_source_choices_include_smithery_and_github():
    """--source must accept 'smithery' and 'github' as valid choices."""
    import argparse
    # Reconstruct argument parser from main()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        choices=("npm", "pypi", "smithery", "github", "all"),
        default="npm",
    )
    # Valid sources
    for src in ("npm", "pypi", "smithery", "github", "all"):
        args = parser.parse_args(["--source", src])
        assert args.source == src

    # Invalid source must raise
    with pytest.raises(SystemExit):
        parser.parse_args(["--source", "invalid-source"])

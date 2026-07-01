"""Corvus — MCP server security testing framework."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__: str = _pkg_version("cobaltosec-corvus")
except PackageNotFoundError:
    __version__ = "0.0.0"

from .core.models import (
    Finding,
    MCPSurface,
    OWASPCategory,
    PromptSpec,
    RawExchange,
    ResourceSpec,
    ScanResult,
    Severity,
    ToolSpec,
)
from .modules.base import ScanModule

__all__ = [
    "__version__",
    "Finding",
    "MCPSurface",
    "OWASPCategory",
    "PromptSpec",
    "RawExchange",
    "ResourceSpec",
    "ScanModule",
    "ScanResult",
    "Severity",
    "ToolSpec",
]

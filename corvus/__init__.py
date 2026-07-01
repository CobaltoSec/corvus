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
from .diff import DiffResult, diff_sarifs
from .modules.base import ScanModule
from .scoring import compute_risk_score, risk_tier, score_result

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
    "DiffResult",
    "diff_sarifs",
    "compute_risk_score",
    "risk_tier",
    "score_result",
    "Severity",
    "ToolSpec",
]

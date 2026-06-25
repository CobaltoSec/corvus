from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RawExchange(BaseModel):
    """Raw JSON-RPC request/response pair captured during a scan."""
    ts: str
    method: str
    params: dict[str, Any]
    result: Any | None = None
    error: str | None = None
    duration_ms: float


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OWASPCategory(str, Enum):
    MCP01_TOOL_POISONING = "MCP01"
    MCP02_PARAM_INJECTION = "MCP02"
    MCP03_SHADOW_TOOL = "MCP03"
    MCP04_INFO_DISCLOSURE = "MCP04"
    MCP05_SCHEMA_BYPASS = "MCP05"
    MCP06_RUG_PULL = "MCP06"
    MCP07_RESPONSE_FLOOD = "MCP07"
    MCP08_AUTH_BYPASS = "MCP08"
    MCP09_SCHEMA_AUDIT = "MCP09"
    MCP10_LOG_AUDIT = "MCP10"
    MCP02_SCOPE_CREEP   = "MCP02-SCOPE"   # temporal — remap completo en v0.8.0
    MCP04_SUPPLY_CHAIN  = "MCP04-SUPPLY"  # temporal — remap completo en v0.8.0


class ToolSpec(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)


class ResourceSpec(BaseModel):
    uri: str
    name: str = ""
    description: str = ""
    mime_type: str | None = None


class PromptSpec(BaseModel):
    name: str
    description: str = ""
    arguments: list[dict[str, Any]] = Field(default_factory=list)


class MCPSurface(BaseModel):
    server_name: str = ""
    server_version: str = ""
    protocol_version: str = ""
    tools: list[ToolSpec] = Field(default_factory=list)
    resources: list[ResourceSpec] = Field(default_factory=list)
    prompts: list[PromptSpec] = Field(default_factory=list)


class Finding(BaseModel):
    id: str = ""
    owasp_category: OWASPCategory
    severity: Severity
    title: str
    description: str
    tool_name: str | None = None
    parameter: str | None = None
    payload: str | None = None
    evidence: str | None = None
    remediation: str = ""
    exploitation_confirmed: bool = False
    confidence: int = 50  # 0-100; how confident we are this is a real finding


class ScanResult(BaseModel):
    target: str
    transport: str
    surface: MCPSurface
    findings: list[Finding] = Field(default_factory=list)
    modules_run: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
    exchanges: list[RawExchange] = Field(default_factory=list)

    @property
    def finding_count(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


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
    MCP09_SCHEMA_AUDIT = "MCP09"


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


class ScanResult(BaseModel):
    target: str
    transport: str
    surface: MCPSurface
    findings: list[Finding] = Field(default_factory=list)
    modules_run: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def finding_count(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

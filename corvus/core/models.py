from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


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
    # OWASP MCP Top 10 (official IDs — v0.8.0 remap)
    MCP01_TOKEN_EXPOSURE    = "MCP01"  # Token Mismanagement & Secret Exposure
    MCP02_SCOPE_CREEP       = "MCP02"  # Privilege Escalation via Scope Creep
    MCP03_TOOL_POISONING    = "MCP03"  # Tool Poisoning
    MCP04_SUPPLY_CHAIN      = "MCP04"  # Supply Chain Attacks
    MCP05_CMD_INJECTION     = "MCP05"  # Command Injection & Execution
    MCP06_RUG_PULL          = "MCP06"  # Intent Flow Subversion (Rug Pull)
    MCP07_AUTH_AUDIT        = "MCP07"  # Insufficient Auth & Authorization
    MCP08_LOG_AUDIT         = "MCP08"  # Lack of Audit and Telemetry
    MCP09_SHADOW_SERVER     = "MCP09"  # Shadow MCP Servers (non-scannable — out-of-scope)
    MCP10_CONTEXT_INJECTION = "MCP10"  # Context Injection & Over-Sharing
    # Extensions (not in official Top 10)
    EXT01_SCHEMA_BYPASS     = "EXT01"  # Schema Validation Bypass
    EXT02_SCHEMA_AUDIT      = "EXT02"  # Schema Audit
    EXT03_SHADOW_TOOL       = "EXT03"  # Shadow Tool Detection
    EXT04_SSRF              = "EXT04"  # Server-Side Request Forgery
    EXT05_RESOURCE_URI      = "EXT05"  # Resource URI Exposure
    EXT06_TOOL_CHAINING     = "EXT06"  # Cross-tool Instruction Chaining
    EXT08_SAMPLING_INJECTION  = "EXT08"  # Sampling/createMessage injection
    EXT09_ELICITATION_PHISHING = "EXT09"  # Elicitation/create phishing
    EXT10_COMPLETION_PROBE      = "EXT10"  # completion/complete injection & enumeration
    EXT11_LOG_LEVEL_ABUSE       = "EXT11"  # logging/setLevel abuse
    EXT12_PROMPT_INJECTION      = "EXT12"  # prompts/get template injection
    EXT13_CURSOR_MANIPULATION   = "EXT13"  # Pagination cursor IDOR/overflow
    EXT14_CANCELLATION_RACE     = "EXT14"  # notifications/cancelled race condition


_CVSS_VECTORS: dict[str, str] = {
    # OWASP MCP Top 10
    "MCP01": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",   # Token Exposure — confidentiality impact, scope change
    "MCP02": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",   # Scope Creep — priv escalation
    "MCP03": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",   # Tool Poisoning — user-triggered
    "MCP04": "AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",   # Supply Chain — complex, deep impact
    "MCP05": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",   # Command Injection — full RCE
    "MCP06": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",   # Rug Pull — intent subversion
    "MCP07": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # Auth Bypass — unauthorized access
    "MCP08": "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",   # Lack of Audit — security gap
    "MCP09": "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",   # Shadow Server — covert channel
    "MCP10": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",   # Context Injection
    # Extensions
    "EXT01": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",   # Schema Bypass — input validation bypass
    "EXT02": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",   # Schema Audit — weak schema definition
    "EXT03": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",   # Shadow Tool — hidden functionality
    "EXT04": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",   # SSRF — internal network access
    "EXT05": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",   # Resource URI — path traversal / exposure
    "EXT06": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",   # Tool Chaining — cross-tool escalation
    "EXT08": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",   # Sampling Injection — LLM hijack
    "EXT09": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",   # Elicitation Phishing — credential harvest
    "EXT10": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",   # Completion Probe — autocomplete enumeration
    "EXT11": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",   # Log Level Abuse — verbose logging
    "EXT12": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",   # Prompt Template Injection
    "EXT13": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",   # Cursor IDOR — pagination abuse
    "EXT14": "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L",   # Cancellation Race — race condition
}


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
    cvss_vector: str | None = None  # CVSS v3.1 base vector; auto-populated from owasp_category if not set

    @model_validator(mode="after")
    def _populate_cvss(self) -> "Finding":
        if self.cvss_vector is None:
            self.cvss_vector = _CVSS_VECTORS.get(self.owasp_category.value)
        return self


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

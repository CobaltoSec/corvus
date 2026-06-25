"""D5 — OWASP ID remap verification (v0.8.0).

Asserts that every built-in module declares the official OWASP MCP Top 10 ID
(or an EXT-prefixed extension ID for modules not in the official Top 10).
"""
import pytest

from corvus.modules.static.tool_poisoning import ToolPoisoningModule
from corvus.modules.static.shadow_tool import ShadowToolModule
from corvus.modules.static.auth_audit import AuthAuditModule
from corvus.modules.static.log_audit import LogAuditModule
from corvus.modules.static.schema_audit import SchemaAuditModule
from corvus.modules.static.scope_audit import ScopeAuditModule
from corvus.modules.static.supply_chain import SupplyChainModule
from corvus.modules.dynamic.token_exposure import TokenExposureModule
from corvus.modules.dynamic.cmd_injection import CmdInjectionModule
from corvus.modules.dynamic.schema_bypass import SchemaBypassModule
from corvus.modules.dynamic.response_flood import ResponseFloodModule
from corvus.modules.dynamic.rug_pull import RugPullModule


@pytest.mark.parametrize("module_cls,expected_name,expected_id", [
    # OWASP MCP Top 10 — official IDs
    (TokenExposureModule,  "token-exposure",  "MCP01"),
    (ScopeAuditModule,     "scope-audit",     "MCP02"),
    (ToolPoisoningModule,  "tool-poisoning",  "MCP03"),
    (SupplyChainModule,    "supply-chain",    "MCP04"),
    (CmdInjectionModule,   "cmd-injection",   "MCP05"),
    (RugPullModule,        "rug-pull",        "MCP06"),
    (AuthAuditModule,      "auth-audit",      "MCP07"),
    (LogAuditModule,       "log-audit",       "MCP08"),
    (ResponseFloodModule,  "response-flood",  "MCP10"),
    # Extensions (not in official Top 10)
    (SchemaBypassModule,   "schema-bypass",   "EXT01"),
    (SchemaAuditModule,    "schema-audit",    "EXT02"),
    (ShadowToolModule,     "shadow-tool",     "EXT03"),
])
def test_module_owasp_id(module_cls, expected_name, expected_id):
    """Each module must declare the correct official OWASP MCP Top 10 ID."""
    assert module_cls.name == expected_name, (
        f"{module_cls.__name__}.name = '{module_cls.name}', expected '{expected_name}'"
    )
    assert module_cls.owasp_id == expected_id, (
        f"{module_cls.__name__}.owasp_id = '{module_cls.owasp_id}', expected '{expected_id}'"
    )

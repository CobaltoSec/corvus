# Corvus

[![PyPI](https://img.shields.io/pypi/v/cobaltosec-corvus)](https://pypi.org/project/cobaltosec-corvus/)
[![Tests](https://github.com/CobaltoSec/corvus/actions/workflows/ci.yml/badge.svg)](https://github.com/CobaltoSec/corvus/actions)
[![Python](https://img.shields.io/pypi/pyversions/cobaltosec-corvus)](https://pypi.org/project/cobaltosec-corvus/)

MCP server security testing framework. Tests MCP servers against the [OWASP MCP Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — both static analysis and live dynamic probing.

```
Corvus v0.9.1  MCP Security Scanner
Target     : python my_mcp_server.py
Transport  : stdio
Modules    : tool-poisoning, scope-audit, shadow-tool, supply-chain, auth-audit,
             log-audit, schema-audit, cmd-injection, token-exposure, schema-bypass,
             response-flood, rug-pull, ssrf, endpoint-probe, param-smuggling,
             init-audit, proto-fuzz, output-encoding

Enumerating surface...
  Tools      : 12
  Resources  : 3
  Prompts    : 2
  Server     : my-server 1.0.0

[MCP03] Tool Poisoning (static)
  [HIGH] Potential prompt injection in description of 'execute_code'

[MCP05] Command Injection (dynamic)
  [HIGH] Command injection confirmed in tool 'run_shell', param 'command'
  [MEDIUM] Path traversal accepted in tool 'read_file', param 'path'

...

─── Summary ──────────────────────────────────────────────────────────────────
  CRITICAL  0   HIGH  2   MEDIUM  1   LOW  3   INFO  4
  Session   : corvus-sessions/20260608-143022/
```

## Install

```bash
pip install cobaltosec-corvus
```

Or from source:

```bash
git clone https://github.com/CobaltoSec/corvus
cd corvus
pip install -e ".[dev]"
```

## Quick Start

```bash
# Scan a stdio MCP server
corvus scan --transport stdio --cmd "python my_server.py"

# Scan an HTTP MCP server
corvus scan --transport http --url http://localhost:8080

# With authentication header
corvus scan --transport http --url http://localhost:8080 --header "Authorization: Bearer token"

# Static analysis only (no live tool calls)
corvus scan --transport stdio --cmd "python my_server.py" --module static

# Specific module
corvus scan --transport stdio --cmd "python my_server.py" --module cmd-injection

# SARIF output (for CI/CD integration)
corvus scan --transport stdio --cmd "python my_server.py" --sarif

# Fail CI on findings above threshold
corvus scan --transport stdio --cmd "python my_server.py" --fail-on high

# Load config from file
corvus scan --config corvus.toml

# Filter low-confidence findings (0-100)
corvus scan --transport stdio --cmd "python my_server.py" --min-confidence 70

# Capture raw JSON-RPC exchanges
corvus scan --transport stdio --cmd "python my_server.py" --log-requests

# List available modules
corvus list-modules
```

## Batch Scan

Scan multiple MCP servers in one invocation:

```yaml
# targets.yaml
targets:
  - name: filesystem
    transport: stdio
    cmd: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]

  - name: my-http-server
    transport: http
    url: http://localhost:8080
```

```bash
corvus batch targets.yaml --output-dir results/ --sarif --min-confidence 70
```

Produces a per-target `report.json` and a top-level `summary.md` table.

## Modules

18 built-in modules covering the full OWASP MCP Top 10 plus protocol and supply chain extensions:

### Static modules (no live tool calls)

| Name | OWASP | What it tests |
|------|-------|---------------|
| `tool-poisoning` | MCP03 | Hidden instructions, obfuscation, and prompt injection patterns in tool descriptions |
| `shadow-tool` | EXT03 | Tool names and descriptions signaling dangerous operations — namespace squatting, trust hijacking |
| `scope-audit` | MCP02 | Credential and PII fields in tool `inputSchema` — tools that request passwords, tokens, or SSNs as parameters |
| `supply-chain` | MCP04 | Known-vulnerable npm packages extracted from the server command (`npm audit`) |
| `auth-audit` | MCP07 | Tool names and descriptions suggesting missing, optional, or bypassable authentication |
| `log-audit` | MCP08 | Tools exposing or tampering with audit logs — enables anti-forensic techniques or leaks operational data |
| `schema-audit` | EXT02 | Weak schema definitions (missing required fields, unconstrained types) that expand the attack surface |

### Dynamic modules (live tool calls)

| Name | OWASP | What it tests |
|------|-------|---------------|
| `cmd-injection` | MCP05 | Command, path, SQL, and prompt injection payloads per parameter — schema-aware, confirmation-required |
| `token-exposure` | MCP01 | Credentials, filesystem paths, stack traces, and tokens leaked in tool responses |
| `proto-fuzz` | EXT01 | Protocol-level crash testing — unknown methods, oversized method names, null request IDs |
| `param-smuggling` | EXT01 | Hidden parameter backdoors — appends undeclared params and measures behavior differences |
| `schema-bypass` | EXT01 | Whether tools properly reject inputs that violate their declared schema |
| `ssrf` | EXT04 | SSRF via URL/host parameters — probes internal metadata endpoints, measures timing anomalies |
| `endpoint-probe` | MCP01 | Path traversal, SSRF, template injection, and credential exposure via `resources/read` and `prompts/get` |
| `output-encoding` | MCP10 | Invisible Unicode in tool outputs — control chars, zero-width chars, bidi overrides that hide malicious content |
| `response-flood` | MCP10 | Excessively large or repetitive responses that overflow an LLM context window |
| `rug-pull` | MCP06 | Re-enumerates the server after dynamic testing; diffs to detect tools added, removed, or mutated mid-session |
| `init-audit` | MCP07 | Audits the initialize handshake — serverInfo injection chars, protocol version downgrade acceptance |

### Module groups

```bash
# All modules (default)
--module all

# Static only (no live calls to the server)
--module static

# Dynamic only
--module dynamic

# Individual module
--module cmd-injection
```

## Transports

### stdio

Spawns the server process and communicates via stdin/stdout. Supports any command:

```bash
corvus scan --transport stdio --cmd "python server.py"
corvus scan --transport stdio --cmd "npx @modelcontextprotocol/server-filesystem /tmp"
corvus scan --transport stdio --cmd "uvx my-mcp-server --arg value"
```

### HTTP

Connects to a running HTTP/SSE MCP server:

```bash
corvus scan --transport http --url http://localhost:8080

# With auth
corvus scan --transport http --url http://localhost:8080 --header "Authorization: Bearer $TOKEN"
corvus scan --transport http --url http://localhost:8080 --header "X-API-Key: secret"
```

## Config File

Create `corvus.toml` to avoid repeating CLI flags:

```toml
[scan]
transport = "stdio"
cmd = "python my_server.py"
modules = "all"
timeout = 30
sarif = false
fail_on = "high"

[scan.headers]
"Authorization" = "Bearer my-token"
```

Then run:

```bash
corvus scan --config corvus.toml
```

CLI flags override config file values. The `--config` flag also accepts absolute paths.

## CLI Reference

```
Usage: corvus scan [OPTIONS]

 Scan an MCP server for security vulnerabilities.

Options:
  -t, --transport  TEXT     stdio | http  (overrides config)
  --cmd            TEXT     Command to launch MCP server (stdio)
  --url            TEXT     URL of MCP server (http)
  -m, --module     TEXT     all | static | dynamic | <module-name>  (overrides config)
  -o, --output-dir PATH
  --fail-on        TEXT     Exit 1 if findings at this severity or above
                            (critical|high|medium|low)
  --timeout        INTEGER  Request timeout in seconds (overrides config)
  --sarif                   Also write SARIF 2.1.0 report
  --header         TEXT     HTTP header "Key: Value" (repeatable, for http transport)
  -c, --config     PATH     Path to corvus.toml config file
  --plugin-dir     TEXT     Directory to load external modules from (repeatable)
  --help                    Show this message and exit.
```

Other commands:

```bash
corvus list-modules              # list available modules with OWASP ID and type
corvus list-modules --plugin-dir ./plugins/   # include external plugins
corvus version                   # print version
```

## Output

Each scan creates a session directory under `corvus-sessions/<timestamp>/`:

```
corvus-sessions/20260608-143022/
├── report.json     # full structured result
├── report.md       # human-readable with remediation guidance
└── report.sarif    # SARIF 2.1.0 (only when --sarif is passed)
```

### SARIF integration

SARIF output is compatible with GitHub Advanced Security, VS Code SARIF Viewer, and any CI pipeline that consumes SARIF:

```yaml
# GitHub Actions example
- name: Run Corvus
  run: corvus scan --transport stdio --cmd "python server.py" --sarif --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: corvus-sessions/
```

## CI Integration

```bash
# Exit 1 if any CRITICAL findings
corvus scan --transport stdio --cmd "python server.py" --fail-on critical

# Exit 1 if any HIGH or above
corvus scan --transport stdio --cmd "python server.py" --fail-on high
```

Severity levels (ascending): `info` → `low` → `medium` → `high` → `critical`

## Plugin System

Add custom modules without modifying Corvus source.

### Directory-based plugins

```bash
corvus scan --transport stdio --cmd "python server.py" --plugin-dir ./my-modules/
```

Each `.py` file in the directory is loaded as a module. The file must define a class that inherits from `BaseModule`:

```python
from corvus.modules.base import BaseModule, Finding, Severity

class MyCustomModule(BaseModule):
    name = "my-check"
    owasp_id = "MCP-CUSTOM"
    module_type = "static"
    description = "Custom check for my organization"

    async def run(self, surface, transport):
        findings = []
        for tool in surface.tools:
            if "dangerous_pattern" in tool.description:
                findings.append(Finding(
                    rule_id="MY001",
                    tool_name=tool.name,
                    severity=Severity.HIGH,
                    title="Dangerous pattern detected",
                    description=f"Tool '{tool.name}' contains a dangerous pattern.",
                    remediation="Remove or sanitize the pattern.",
                ))
        return findings
```

### Package-based plugins

Register via `pyproject.toml` entry points:

```toml
[project.entry-points."corvus.modules"]
my-check = "my_package.modules.my_check:MyCustomModule"
```

After `pip install my-package`, Corvus auto-discovers the module.

## Research: MCP Ecosystem Security Audit

Corvus has been battle-tested against the real-world MCP ecosystem across two case studies — 43 servers audited, spanning official `@modelcontextprotocol` packages, community servers, and the broader npm ecosystem.

| | CS01 (Tier A/B/C) | CS02 (Tier D) | Combined |
|---|---|---|---|
| Servers audited | 23 | 20 | **43** |
| True positives | 43 | 12 | **55** |
| HIGH findings | 27 | 10 | **37** |
| CRITICAL findings | 1 | 0 | **1** |
| FP rate | 30.6% | 40% | ~34% |

Key findings from the wild:

- **35% of MCP servers crash** on a single malformed JSON-RPC request — reproducible DoS with no authentication required
- **Shadow tool injection** confirmed in `mcp-server-docker`, `postgres-mcp-server`, `lsp-mcp-server` — tool descriptions that instruct an AI agent to execute arbitrary operations
- **Supply chain cascade**: `@modelcontextprotocol/sdk ≤1.25.1` advisory propagates to the majority of JS-based servers in the ecosystem
- **Invisible Unicode** (zero-width chars, bidi overrides) in tool descriptions — undetectable to human reviewers, can manipulate AI agent reasoning
- **65% of audited servers** have at least one HIGH-severity confirmed finding

Full datasets, curated findings, and methodology in [`case-studies/`](case-studies/).

### Responsible Disclosure

| Advisory | Package | Finding | Status |
|----------|---------|---------|--------|
| [GHSA-mf64-cgv4-ppcx](https://github.com/advisories/GHSA-mf64-cgv4-ppcx) | @playwright/mcp | Path traversal via filesystem tools | Coordinated disclosure (MSRC) |
| [GHSA-7w27-7xwv-x6x2](https://github.com/advisories/GHSA-7w27-7xwv-x6x2) | mcp-server-sqlite | SQL injection via query tools | Disclosed |
| [GHSA-7763-c5gf-v5fj](https://github.com/advisories/GHSA-7763-c5gf-v5fj) | mcp-shell-server | Command injection via shell tools | Disclosed |
| [GHSA-pr6r-h66r-m47j](https://github.com/advisories/GHSA-pr6r-h66r-m47j) | server-everything | Token exposure via env tool | Disclosed |

## Development

```bash
git clone https://github.com/CobaltoSec/corvus
cd corvus
pip install -e ".[dev]"
pytest
```

## License

MIT

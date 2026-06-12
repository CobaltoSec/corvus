# Corvus

MCP server security testing framework. Tests MCP servers against the [OWASP MCP Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — both static analysis and live dynamic probing.

```
Corvus v0.5.1  MCP Security Scanner
Target     : python my_mcp_server.py
Transport  : stdio
Modules    : tool-poisoning, schema-audit, shadow-tool, auth-audit, log-audit,
             param-injection, info-disclosure, schema-bypass, response-flood, rug-pull

Enumerating surface...
  Tools      : 12
  Resources  : 3
  Prompts    : 2
  Server     : my-server 1.0.0

[MCP01] Tool Poisoning (static)
  [HIGH] Potential prompt injection in description of 'execute_code'

[MCP02] Parameter Injection (dynamic)
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
corvus scan --transport stdio --cmd "python my_server.py" --module param-injection

# SARIF output (for CI/CD integration)
corvus scan --transport stdio --cmd "python my_server.py" --sarif

# Fail CI on findings above threshold
corvus scan --transport stdio --cmd "python my_server.py" --fail-on high

# Load config from file
corvus scan --config corvus.toml

# List available modules
corvus list-modules
```

## Modules

Full coverage of OWASP MCP Top 10:

| Name | OWASP | Type | What it tests |
|------|-------|------|---------------|
| `tool-poisoning` | MCP01 | static | Hidden instructions, obfuscation, and prompt injection patterns in tool descriptions |
| `param-injection` | MCP02 | dynamic | Command, path, prompt, and SQL injection payloads per parameter — schema-aware |
| `shadow-tool` | MCP03 | static | Tool names that shadow built-ins or signal dangerous operations (namespace squatting, trust hijacking) |
| `info-disclosure` | MCP04 | dynamic | Credentials, filesystem paths, stack traces, and tokens leaked in tool responses |
| `schema-bypass` | MCP05 | dynamic | Whether tools properly reject inputs that violate their declared schema |
| `rug-pull` | MCP06 | dynamic | Re-enumerates the server after dynamic testing; diffs against initial snapshot to detect added, removed, or mutated tools |
| `response-flood` | MCP07 | dynamic | Excessively large or highly repetitive responses that could overflow an LLM context window or inject looping instructions |
| `auth-audit` | MCP08 | static | Tool names and descriptions suggesting missing, optional, or bypassable authentication |
| `schema-audit` | MCP09 | static | Weak schema definitions (missing required fields, unconstrained types) that expand the attack surface |
| `log-audit` | MCP10 | static | Tools that expose or tamper with audit logs — enables anti-forensic techniques or leaks operational data |

### Module groups

```bash
# All modules (default)
--module all

# Static only (no live calls to the server)
--module static

# Dynamic only
--module dynamic

# Individual module
--module param-injection
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

## Development

```bash
git clone https://github.com/CobaltoSec/corvus
cd corvus
pip install -e ".[dev]"
pytest
```

## License

MIT

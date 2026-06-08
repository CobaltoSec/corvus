# Corvus

MCP server security testing framework. Discovers the attack surface of an MCP server and runs targeted tests across OWASP MCP Top 10 categories.

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

## Usage

```bash
# Scan a local MCP server (stdio transport)
corvus scan --transport stdio --cmd "python my_server.py"

# Static analysis only (no tool calls)
corvus scan --transport stdio --cmd "python my_server.py" --module static

# Specific module
corvus scan --transport stdio --cmd "python my_server.py" --module param-injection

# HTTP transport
corvus scan --transport http --url http://localhost:8080

# CI mode — exit 1 if any HIGH or above
corvus scan --transport stdio --cmd "python my_server.py" --fail-on high

# List available modules
corvus list-modules
```

## Modules

| Name | OWASP | Type | What it tests |
|------|-------|------|---------------|
| `tool-poisoning` | MCP01 | static | Hidden instructions in tool descriptions |
| `schema-audit` | MCP09 | static | Weak schema definitions |
| `param-injection` | MCP02 | dynamic | Command/path/prompt/SQL injection per parameter |
| `info-disclosure` | MCP04 | dynamic | Sensitive data leaked in responses |
| `schema-bypass` | MCP05 | dynamic | Acceptance of out-of-schema inputs |

## Transports

- **stdio** — spawns the server process and communicates via stdin/stdout (most common)
- **http** — connects to a running HTTP/SSE server *(coming soon)*

## Output

Each scan writes to `corvus-sessions/<timestamp>/`:
- `report.json` — full structured result
- `report.md` — human-readable report with remediation guidance

## License

MIT

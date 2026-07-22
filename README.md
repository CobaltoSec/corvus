# Corvus

[![PyPI](https://img.shields.io/pypi/v/cobaltosec-corvus)](https://pypi.org/project/cobaltosec-corvus/)
[![Tests](https://github.com/CobaltoSec/corvus/actions/workflows/ci.yml/badge.svg)](https://github.com/CobaltoSec/corvus/actions)
[![Python](https://img.shields.io/pypi/pyversions/cobaltosec-corvus)](https://pypi.org/project/cobaltosec-corvus/)

> ⭐ **If Corvus found a vulnerability in your MCP server, [star the repo](https://github.com/CobaltoSec/corvus)** — it helps other security teams discover the tool.

> **Vulnerabilities found:** [GHSA-hv3x](https://github.com/advisories/GHSA-hv3x-m9fv-4vhf) (mcp-server-git, DoS HIGH) · [GHSA-43j9](https://github.com/advisories/GHSA-43j9-hmpq-cgv7) (remnux-mcp-server, RCE MEDIUM) · [GHSA-jgxf](https://github.com/advisories/GHSA-jgxf-j67w-w284) (campertunity-ai-tools, SSRF HIGH) · [GHSA-3f55](https://github.com/advisories/GHSA-3f55-qgq4-f88c) (server-sequential-thinking, DoS MEDIUM) — [+46 in coordinated disclosure](case-studies/DISCLOSURE-PROCESS.md)

MCP server security testing framework. Tests MCP servers against the [OWASP MCP Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — both static analysis and live dynamic probing.

```
Corvus v1.3.1  MCP Security Scanner
Target     : python my_mcp_server.py
Transport  : stdio
Modules    : tool-poisoning, scope-audit, shadow-tool, supply-chain, osv-supply-chain,
             github-advisory, npm-behavior, supply-chain-python, auth-audit, log-audit,
             schema-audit, resource-uri, tool-chaining, cmd-injection, token-exposure,
             ssrf, endpoint-probe, param-smuggling, schema-bypass, proto-fuzz, batch-dos,
             output-encoding, response-flood, response-injection, rug-pull, init-audit,
             oauth-bypass, sampling-probe, elicitation-probe, completion-probe,
             logging-probe, prompts-injection, cursor-probe, cancellation-probe

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
  Risk Score: 56 / 100 (HIGH)
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
# Try it now — scan a real MCP server in one command (needs Node.js):
pip install cobaltosec-corvus
corvus scan "npx -y @modelcontextprotocol/server-filesystem /tmp"
```

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

# Rate-limit probes (ms between requests)
corvus scan --transport stdio --cmd "python my_server.py" --delay 500

# Pass environment variables to the server process
corvus scan --transport stdio --cmd "python my_server.py" --env API_KEY=secret --env DEBUG=1

# Print Risk Score at the end
corvus scan --transport stdio --cmd "python my_server.py" --score

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

<!-- CORVUS_MODULES_START -->
34 built-in modules covering the full OWASP MCP Top 10 plus protocol, elicitation, sampling, OAuth and supply chain extensions:

### Static modules (no live tool calls)

| Name | OWASP | What it tests |
|------|-------|---------------|
| `tool-poisoning` | MCP03 | Hidden instructions, obfuscation, and prompt injection patterns in tool descriptions |
| `shadow-tool` | EXT03 | Tool names signaling dangerous operations — namespace squatting, covert chaining, trust hijacking |
| `scope-audit` | MCP02 | Credential and PII fields in tool inputSchema — tools that request passwords, tokens, or SSNs |
| `supply-chain` | MCP04 | Known-vulnerable npm packages extracted from the server command (npm audit) |
| `supply-chain-python` | MCP04 | Known-vulnerable Python packages extracted from the server environment (pip list) |
| `osv-supply-chain` | MCP04 | Queries OSV.dev API for known vulnerabilities in detected dependencies |
| `github-advisory` | MCP04 | Queries GitHub Security Advisories for known vulnerabilities in detected packages |
| `npm-behavior` | MCP04 | Queries npm registry for suspicious install scripts (postinstall, preinstall) in detected packages |
| `auth-audit` | MCP07 | Tool names and descriptions suggesting missing, optional, or bypassable authentication |
| `log-audit` | MCP08 | Tools exposing or tampering with audit logs — anti-forensic techniques or operational data leaks |
| `schema-audit` | EXT02 | Weak schema definitions (missing required fields, unconstrained types) that expand the attack surface |
| `resource-uri` | EXT05 | Static analysis of resources/list URIs — detects sensitive schemes (file://, env://, exec://) |
| `tool-chaining` | EXT03 | Detects tool descriptions that covertly chain additional tool calls or bypass user confirmation |

### Dynamic modules (live tool calls)

| Name | OWASP | What it tests |
|------|-------|---------------|
| `cmd-injection` | MCP05 | Command, path, SQL, and prompt injection payloads per parameter — schema-aware, confirmation-required |
| `token-exposure` | MCP01 | Credentials, filesystem paths, stack traces, and tokens leaked in tool responses |
| `ssrf` | EXT04 | SSRF via URL/host parameters — probes internal metadata endpoints, measures timing anomalies |
| `endpoint-probe` | MCP01 | Path traversal, SSRF, template injection, and credential exposure via resources/read and prompts/get |
| `param-smuggling` | EXT01 | Hidden parameter backdoors — appends undeclared params and measures behavior differences |
| `schema-bypass` | EXT01 | Whether tools properly reject inputs that violate their declared schema |
| `proto-fuzz` | EXT01 | Protocol-level crash testing — unknown methods, oversized method names, null request IDs |
| `batch-dos` | EXT01 | Sends JSON-RPC 2.0 batch arrays and oversized payloads to detect crash/DoS conditions |
| `output-encoding` | MCP10 | Invisible Unicode in tool outputs — control chars, zero-width chars, bidi overrides |
| `response-flood` | MCP10 | Excessively large or repetitive responses that overflow an LLM context window |
| `response-injection` | MCP10 | Detects injected content (HTML/JS/markdown directives) in benign tool responses |
| `rug-pull` | MCP06 | Re-enumerates the server after dynamic testing; diffs to detect tools added, removed, or mutated mid-session |
| `init-audit` | MCP07 | Audits the initialize handshake — serverInfo injection chars, protocol version downgrade acceptance |
| `oauth-bypass` | MCP07 | Tests HTTP transport endpoints for authentication bypass: missing auth, invalid Bearer, URL-embedded creds |
| `sampling-probe` | EXT08 | Detects malicious MCP sampling/createMessage — prompt injection, context exfil, unsolicited calls |
| `elicitation-probe` | EXT09 | Detects MCP elicitation/create misuse — credential phishing, sensitive data schemas |
| `completion-probe` | EXT10 | Probes MCP completion/complete endpoint for prompt injection via argument context |
| `logging-probe` | EXT11 | Tests whether the server allows unauthenticated external log level manipulation |
| `prompts-injection` | EXT12 | Detects prompt injection via MCP prompts/get — static patterns + live argument injection |
| `cursor-probe` | EXT13 | Tests MCP pagination cursor handling for path traversal, oversized values, and injection |
| `cancellation-probe` | EXT14 | Tests MCP notifications/cancelled handling for race conditions and crash on unknown requestIds |

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
<!-- CORVUS_MODULES_END -->

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
corvus init                      # generate a corvus.toml skeleton in the current directory
corvus report REPORT.json        # regenerate MD/SARIF/HTML from an existing report.json
corvus diff OLD.sarif NEW.sarif  # compare two SARIF files: new / fixed / unchanged findings
corvus score REPORT.json         # print Risk Score (0-100) for a report
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

<!-- CORVUS_RESEARCH_START -->
Corvus has been battle-tested against the real-world MCP ecosystem across 16 case studies — 315 servers audited, spanning official `@modelcontextprotocol` packages, community servers, and the broader npm and PyPI ecosystem.

| Metric | Total (16 case studies) |
|--------|-------------------------------|
| Servers audited | **315** |
| Raw findings | **~4190** |
| True positives | **~1314** |

Key findings from the wild:

- **100% of MCP servers tested crash on a 37-byte notifications/cancelled payload with unknown requestId (EXT14) — universal DoS requiring zero authentication**
- **37% of servers crash on spec-compliant JSON-RPC batch arrays or oversized method names — reproducible DoS without authentication**
- **71% of servers accept arbitrary protocolVersion strings during the initialize handshake — protocol downgrade accepted**
- **SSRF confirmed in 3 servers (myclaw-toolkit, @sap-ux/fiori-mcp-server, markitdown-mcp) — internal metadata endpoints reachable from tool parameters**
- **Supply chain cascade: @modelcontextprotocol/sdk ≤1.25.1 advisory propagates to the majority of JS-based servers in the ecosystem**
- **FP rate reduced from ~40% (v0.5.0, early calibration) to ~7% (CS03, v1.0.1) through 5 calibration iterations**
- **CS04 introduces 3 new systematic FP patterns: docs server lazy-loading (MCP06, 195 FP from sveltejs), Python strptime error reflection (MCP05, 33 FP), and third-party API error message echo (MCP05, 62+ FP across 11 servers)**
- **Novel attack pattern discovered: SaaS description mutation rug-pull — mcp-devutils changes 29 tool descriptions mid-session from '[PRO — trial]' to '[PRO — trial expired]' based on billing logic**
- **Covert AI agent surveillance via MCP scope creep: clarvia-mcp-server instructs agents to 'Use after every tool invocation' to report all activity to external servers**
- **SSRF with timing evidence: pulsemcp-pulse-fetch scrape.url accesses 169.254.169.254 AWS metadata endpoint (8.3s timing delta vs 2.3s baseline)**
- **Stored SQL injection pattern: arxiv-mcp-server watch_topic.topic stores SQL payload in database without sanitization (plausible, needs check_alerts verification)**
- **Anti-forensic log erasure: godot-mcp-server exposes clear_console_log tool (CRITICAL, MCP08) — combined with write-path traversal in save_resource_to_file/take_screenshot enables exfiltrate-then-cover-tracks chain**
- **XSS response injection pattern confirmed across ecosystems: functype-mcp-server (npm) and awslabs.amazon-kendra-index-mcp-server (PyPI) both reflect unsanitized XSS payloads verbatim in error messages — systematic cross-SDK issue**

Full datasets, curated findings, and methodology in [`case-studies/`](case-studies/).
<!-- CORVUS_RESEARCH_END -->

### Responsible Disclosure

<!-- CORVUS_DISCLOSURE_START -->
53 security advisories filed across 16 case studies — 7 published, 46 in active coordinated disclosure (90-day window).

**Published:**

| Advisory | Package | Severity | Finding |
|----------|---------|----------|---------|
| [GHSA-43j9-hmpq-cgv7](https://github.com/advisories/GHSA-43j9-hmpq-cgv7) | remnux-mcp-server | MEDIUM | Unauthenticated RCE via HTTP transport on non-loopback deployments |
| [GHSA-hv3x-m9fv-4vhf](https://github.com/advisories/GHSA-hv3x-m9fv-4vhf) | mcp-server-git | HIGH | DoS via spec-compliant JSON-RPC batch arrays and oversized method names |
| [GHSA-3f55-qgq4-f88c](https://github.com/advisories/GHSA-3f55-qgq4-f88c) | server-sequential-thinking | MEDIUM | DoS via oversized JSON-RPC method names (CWE-755) |
| [GHSA-jgxf-j67w-w284](https://github.com/advisories/GHSA-jgxf-j67w-w284) | campertunity-ai-tools | HIGH | SSRF via booking API URL parameter — internal metadata endpoints reachable |
| [GHSA-prc4-649r-564g](https://github.com/advisories/GHSA-prc4-649r-564g) | localparse-mcp | HIGH | SSRF confirmed in parse_url — timing and timeout signals confirmed (CWE-918) |
| [GHSA-32vx-mq6h-p8f3](https://github.com/advisories/GHSA-32vx-mq6h-p8f3) | emilia-protocol | HIGH | Prompt template injection via trust_decision/receipt_quality_check + forced compliance gate (EXT03/EXT12) |
| [GHSA-wx78-8jx3-wcv9](https://github.com/advisories/GHSA-wx78-8jx3-wcv9) | @tensorfeed/mcp-server | HIGH | XSS reflection cluster across 6 tools — unsanitized payloads echoed verbatim (MCP05) |

**Active coordinated disclosure (46 advisories):** packages include @playwright/mcp, mcp-server-sqlite, mcp-shell-server, myclaw-toolkit (CRITICAL), @sap-ux/fiori-mcp-server, and others — 90-day embargo window in progress.

Full advisory index: [`case-studies/DISCLOSURE-PROCESS.md`](case-studies/DISCLOSURE-PROCESS.md)
<!-- CORVUS_DISCLOSURE_END -->

## FAQ

**How does Corvus compare to mcp-scan / Snyk Agent Scan?**

[mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) (acquired by Snyk in 2025, now [Snyk Agent Scan](https://github.com/snyk/agent-scan)) is the most widely deployed MCP security tool and does a great job on prompt injection and tool poisoning. If that's your primary concern, it's worth running both.

The tools approach MCP security from different angles:

| | mcp-scan / Snyk Agent Scan | Corvus |
|---|---|---|
| **Scope** | Prompt injection, tool poisoning, toxic flows, cross-origin escalation | Full [OWASP MCP Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — 34 modules |
| **Perspective** | Client-side: reads your MCP config file | Server-side: connects directly via stdio or HTTP |
| **Probing** | Static analysis + optional proxy monitoring | Static analysis + live dynamic probing (actual tool calls with payloads) |
| **CI/CD** | Basic | SARIF output, `--fail-on high`, batch scanning |
| **Coverage** | Prompt injection / poisoning focused | Adds cmd injection, SSRF, auth bypass, supply chain, schema bypass, parameter smuggling, DoS, OAuth, sampling/elicitation misuse |
| **Real-time** | ✅ Proxy mode for live monitoring | ❌ Point-in-time scan only |
| **Disclosures** | No public advisory program | 50 coordinated GHSAs filed |
| **Backing** | Snyk (enterprise) | Independent, security research focused |

**When to use mcp-scan:** you want real-time proxy monitoring of agent traffic, or you need the Snyk enterprise integration.

**When to use Corvus:** you're doing a full security audit, need CI/CD-compatible output, or want to test attack surfaces beyond prompt injection (command injection, SSRF, auth bypass, supply chain, etc.).

They're complementary — mcp-scan excels at runtime monitoring, Corvus at point-in-time depth.

## Development

```bash
git clone https://github.com/CobaltoSec/corvus
cd corvus
pip install -e ".[dev]"
pytest
```

## License

MIT

---

> ⭐ **Corvus is open source and actively maintained.** If it helped you secure your MCP stack, a [GitHub star](https://github.com/CobaltoSec/corvus) goes a long way.

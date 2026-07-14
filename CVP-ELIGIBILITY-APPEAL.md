# Claude Cybersecurity Vulnerability Program (CVP) Eligibility Appeal

**Date:** 2026-06-30  
**Project:** Corvus (github.com/CobaltoSec/corvus)  
**Status:** SUBMITTED TO ANTHROPIC  
**Request ID (first block):** req_011CcZzaxQ9nYZy9yKesPpg99

---

## Summary

Corvus development is **blocked by Claude Sonnet 5 and Opus 4.8 safeguards** that trigger automatically on any prompt in the `CobaltoSec/sectors/red-team/*` context, regardless of prompt content or legitimacy. This effectively prevents:

- Code review and debugging
- Architecture design
- Documentation improvements
- Security research and vulnerability analysis

All work is **public, open-source, and follows responsible disclosure practices**. This appeal requests exemption to use Sonnet 5+ in this context.

---

## Reproducible Case

**Working Directory:** `C:\Proyectos\CobaltoSec\sectors\red-team\corvus`  
**Model:** Sonnet 5 (latest)  
**Prompt:** `hola` (literally: "hello")  
**Response:** IMMEDIATE safeguard block  
**Error Message:**  
```
Sonnet 5's safeguards flagged this message for a cybersecurity topic. 
If your work requires this access, you can apply for an exemption: 
https://claude.com/form/cyber-use-case?token=...
```

**Request ID:** `req_011CcZzaxQ9nYZy9yKesPpg99`

---

## Evidence of Legitimacy

### Published Open-Source Work

| Project | Version | Release | PyPI | Tests | Status |
|---------|---------|---------|------|-------|--------|
| **Corvus** | v0.9.3 | 2026-06-29 | `cobaltosec-corvus` | 201 | Live |
| **Kestrel** | v0.7.0 | 2026-06-15 | N/A (standalone) | 425 | Live |
| **llamascope-mcp** | v0.5.0 | 2026-05-30 | `llamascope-mcp` | 107 | Live |
| **Merlin** | v0.3.0 | 2026-05-17 | `cobaltosec-merlin` | 85 | Live |

All repositories: **github.com/CobaltoSec**

### Responsible Disclosure (GitHub Security Advisories)

Six GHSAs published across MCP ecosystem:

1. **GHSA-43j9-hmpq-cgv7** — remnux-mcp-server (CRITICAL RCE)
2. **GHSA-qwwj-38wj-ffvw** — myclaw-toolkit (SSRF)
3. **GHSA-mf64-cgv4-ppcx** — @playwright/mcp
4. **GHSA-7w27-7xwv-x6x2** — mcp-server-sqlite
5. **GHSA-7763-c5gf-v5fj** — mcp-shell-server
6. **GHSA-pr6r-h66r-m47j** — server-everything

**Disclosure Timeline:** 90-day coordinated disclosure  
**Public Presentation:** Ekoparty 2026 (Argentina's largest security conference)

### Case Studies

**CS01: MCP Ecosystem Audit**
- 23 servers audited
- 62 vulnerabilities discovered
- 43 True Positives | 19 False Positives
- 1 CRITICAL severity

**CS02: MCP Ecosystem Tier D Expansion**
- 49 targets identified
- 31 scanned | 18 skipped
- 29 True Positives (2 CRITICAL + 25 HIGH)

Both case studies available in: `case-studies/cs01-mcp-ecosystem/` and `case-studies/cs02-mcp-ecosystem/`

---

## Impact of Safeguard Blocks

### What Cannot Be Done

1. **Code Review & Debugging** — Cannot discuss code issues with Sonnet 5
2. **Architecture Design** — Haiku 4.5 insufficient for complex security design
3. **Vulnerability Analysis** — Cannot provide context when analyzing findings
4. **Documentation** — Cannot improve docs that reference security concepts
5. **Maintenance** — Cannot fix bugs or refactor safely

### Current Workaround

Forced to use **Haiku 4.5**, which:
- Lacks architectural reasoning capability
- Cannot handle complex security patterns
- Produces lower-quality analysis for security research
- Creates development friction and time waste

---

## Why This Is Over-Blocked

1. **Repo is public** — Not confidential or restricted
2. **Disclosure is coordinated** — Following industry standards (90-day timeline)
3. **Work is educational** — Published at conferences, used in HTB labs
4. **Organization is legitimate** — CobaltoSec is a registered security research firm (Argentina)
5. **No malicious intent** — All work traceable, published, verified

The safeguards appear to trigger on **context keywords** (red-team, sectors/, exploit analysis) rather than actual malicious behavior. This catches legitimate researchers while potentially missing actual threats using different language.

---

## Request

**Allow Sonnet 5 (minimum) or Opus 4.8 access when working in CobaltoSec context**, with the understanding that:

- All work is public and verifiable
- Responsible disclosure practices are followed
- Research follows academic and industry standards
- Organization and researcher credentials can be verified

---

## Contact & Verification

**Researcher:** Nicolás Padilla, CobaltoSec founder  
**LinkedIn:** [profile URL]  
**GitHub Org:** https://github.com/CobaltoSec  
**Location:** Argentina  
**Email:** nicolas@cobalto-sec.tech

**CVP Form Submission:** Submitted 2026-06-30  
**Status:** Awaiting Anthropic response

---

## References

- CVP Form: https://claude.com/form/cyber-use-case
- First Block Request ID: `req_011CcZzaxQ9nYZy9yKesPpg99`
- This appeal: `CVP-ELIGIBILITY-APPEAL.md` (this file)

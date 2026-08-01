from __future__ import annotations

import re

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport

# URIs pointing to sensitive system files → CRITICAL
_CRITICAL_URI_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\.ssh/", re.I),
    re.compile(r"/etc/(shadow|passwd|sudoers|ssh/)", re.I),
    re.compile(r"(^|/)\.env($|/)", re.I),
    re.compile(r"/secrets?/", re.I),
    re.compile(r"\.aws/credentials", re.I),
    re.compile(r"\.(npmrc|pypirc)($|/)", re.I),
    re.compile(r"private[_\-]?key", re.I),
    re.compile(r"credentials\.json", re.I),
]

# Web-scheme URIs are not filesystem paths — skip CRITICAL_URI_PATTERNS (educational/API docs FP)
_WEB_URI_RE = re.compile(r"^(https?|ftp|docs|mailto)://", re.I)

# file:// URIs outside safe sandboxed dirs → HIGH
_SAFE_FILE_DIRS = ("/tmp", "/var/app", "/tmp/", "/var/app/")

# URI credential query params → HIGH (captures param name + value for placeholder check)
_CREDENTIAL_QUERY_RE = re.compile(
    r"[?&](token|api_key|secret|password|auth|key|access_token)=([^&\s#]*)",
    re.I,
)

_PLACEHOLDER_URI_RE = re.compile(
    r"^(your[-_]|example[-_]|replace[-_]|my[-_]|test[-_]|sample[-_]|demo[-_]|fake[-_]|mock[-_])"
    r"|^<[^>]+>$|^\[.*\]$|^x{3,}$|^0{4,}$"
    r"|placeholder|changeme",
    re.I,
)

# Servers exposing more than this many resources → MEDIUM (attack surface signal)
_LARGE_SURFACE_THRESHOLD = 20

# Content signatures for verifying sensitive file exposure in resource bodies
_SENSITIVE_CONTENT_SIGNATURES = (
    "root:x:0:0", "daemon:x:", "nobody:x:",       # /etc/passwd
    "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY",  # PEM private keys
    "[default]", "aws_access_key_id",              # AWS credentials
    "password =", "secret_key =",                  # config files with credentials
)

# MIME types that indicate documentation or API responses rather than raw file content
_DOC_MIME_TYPES = ("text/html", "application/json", "text/javascript")


class ResourceUriModule(ScanModule):
    owasp_id = "EXT05"
    category = "Resource URI Exposure"
    name = "resource-uri"
    description = (
        "Static analysis of resources/list URIs — detects sensitive system paths, "
        "file:// scheme abuse, credential query parameters, and oversized resource surfaces"
    )
    is_static = True

    async def _verify_critical(self, transport: MCPTransport, uri: str) -> bool:
        """Mitigate body-only FP: require both response body content and a non-doc MIME type to confirm exposure."""
        try:
            result = await transport.send_request("resources/read", {"uri": uri})
            if not isinstance(result, dict):
                return False
            contents = result.get("contents", [])
            if not contents or not isinstance(contents, list):
                return False
            item = contents[0]
            if not isinstance(item, dict):
                return False
            body = item.get("text", "") or ""
            mime_type = item.get("mimeType", "")
            body_confirmed = any(sig in body for sig in _SENSITIVE_CONTENT_SIGNATURES)
            content_type_ok = not any(t in mime_type for t in _DOC_MIME_TYPES)
            return body_confirmed and content_type_ok
        except Exception:
            return False

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if not surface.resources:
            return findings

        for resource in surface.resources:
            uri = resource.uri

            # CRITICAL: URI points to sensitive system file (skip web-scheme URIs — educational FP)
            for pattern in _CRITICAL_URI_PATTERNS:
                if pattern.search(uri) and not _WEB_URI_RE.match(uri):
                    verified = await self._verify_critical(transport, uri)
                    findings.append(Finding(
                        owasp_category=OWASPCategory.EXT05_RESOURCE_URI,
                        severity=Severity.CRITICAL if verified else Severity.HIGH,
                        title=f"Resource URI — sensitive path exposed: '{uri}'",
                        description=(
                            f"Resource URI '{uri}' matches a pattern associated with sensitive "
                            "system files. Exposing this resource through MCP allows any caller "
                            "to read secrets, credentials, or system configuration."
                        ),
                        evidence=uri,
                        remediation=(
                            "Remove sensitive file paths from the MCP resource surface. "
                            "Use a strict allowlist of safe directories and reject any URI "
                            "outside that allowlist."
                        ),
                        confidence=85,
                    ))
                    break

            else:
                # HIGH: file:// URI outside safe sandboxed dirs
                if uri.lower().startswith("file://"):
                    path = uri[7:]  # strip file://
                    if not any(path.startswith(safe) for safe in _SAFE_FILE_DIRS):
                        findings.append(Finding(
                            owasp_category=OWASPCategory.EXT05_RESOURCE_URI,
                            severity=Severity.HIGH,
                            title=f"Resource URI — file:// outside sandbox: '{uri}'",
                            description=(
                                f"Resource URI '{uri}' uses the file:// scheme pointing outside "
                                "safe sandbox directories (/tmp, /var/app). This may allow "
                                "arbitrary filesystem reads via the MCP resource surface."
                            ),
                            evidence=uri,
                            remediation=(
                                "Restrict file:// URIs to explicitly sandboxed directories. "
                                "Reject any path that resolves outside the intended root."
                            ),
                            confidence=80,
                        ))

                # HIGH: credential material in URI query params (skip placeholder values)
                elif (m := _CREDENTIAL_QUERY_RE.search(uri)) and not _PLACEHOLDER_URI_RE.search(m.group(2)):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.EXT05_RESOURCE_URI,
                        severity=Severity.HIGH,
                        title=f"Resource URI — credential in query param: '{uri[:80]}'",
                        description=(
                            f"Resource URI contains a query parameter name associated with "
                            "credentials or tokens. Embedding secrets in URIs exposes them in "
                            "logs, history, and to any MCP client that enumerates resources."
                        ),
                        evidence=uri[:300],
                        remediation=(
                            "Never embed credentials in URIs. Use request headers or "
                            "server-side credential stores instead."
                        ),
                        confidence=80,
                    ))

        # MEDIUM: oversized resource surface
        if len(surface.resources) > _LARGE_SURFACE_THRESHOLD:
            findings.append(Finding(
                owasp_category=OWASPCategory.EXT05_RESOURCE_URI,
                severity=Severity.MEDIUM,
                title=f"Resource URI — large attack surface ({len(surface.resources)} resources exposed)",
                description=(
                    f"The server exposes {len(surface.resources)} MCP resources "
                    f"(threshold: {_LARGE_SURFACE_THRESHOLD}). A large resource surface "
                    "increases the risk of accidentally exposing sensitive data and makes "
                    "it harder for operators to audit what information is accessible."
                ),
                evidence=f"{len(surface.resources)} resources",
                remediation=(
                    "Audit each exposed resource for necessity. Apply the principle of "
                    "least exposure — only surface resources that callers explicitly need."
                ),
                confidence=60,
            ))

        return findings

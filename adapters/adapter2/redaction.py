"""Redaction helpers for adapter evidence."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

SENSITIVE_NAMES = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie", "cookie2",
    "password", "passwd", "token", "access_token", "refresh_token", "api_key",
    "apikey", "secret", "client_secret", "session", "sessionid", "credential",
})
_CONFIGURED_SECRETS = ()


def configure_secrets(values):
    """Register application-specific secret values for evidence redaction."""
    global _CONFIGURED_SECRETS
    if isinstance(values, (str, bytes)):
        raise TypeError("secrets must be an iterable of strings, not one string")
    clean = []
    for value in values:
        if not isinstance(value, str):
            raise TypeError("configured secrets must be strings")
        if value:
            clean.append(value)
    _CONFIGURED_SECRETS = tuple(sorted(set(clean), key=len, reverse=True))


def _is_sensitive_name(name):
    compact = re.sub(r"[^a-z0-9]", "", str(name).lower())
    return (str(name).lower() in SENSITIVE_NAMES or any(
        marker in compact for marker in
        ("authorization", "cookie", "password", "passwd", "token", "apikey", "secret", "credential", "sessionid")
    ))


def redact_headers(headers):
    return {
        key: "[REDACTED]" if _is_sensitive_name(key) else sanitize_snippet(value, 2000)
        for key, value in (headers or {}).items()
    }


def redact_url(url: str) -> str:
    try:
        parts = urlsplit(str(url))
        host = parts.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        try:
            port = parts.port
        except ValueError:
            return "[INVALID_URL]"
        safe_netloc = host + (f":{port}" if port is not None else "")
    except (TypeError, ValueError):
        return "[INVALID_URL]"
    query = [
        (key, "[REDACTED]" if _is_sensitive_name(key)
         else value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    sanitized = urlunsplit((parts.scheme, safe_netloc, parts.path, urlencode(query), ""))
    for secret in _CONFIGURED_SECRETS:
        sanitized = sanitized.replace(secret, "[REDACTED]")
        sanitized = sanitized.replace(quote(secret, safe=""), "[REDACTED]")
    return sanitized


def sanitize_snippet(value, limit=500):
    text = "" if value is None else str(value)
    for secret in _CONFIGURED_SECRETS:
        text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", r"\1 [REDACTED]", text)
    text = re.sub(
        r"(?i)(authorization|proxy-authorization|cookie|set-cookie|password|passwd|"
        r"access_token|refresh_token|token|api[_-]?key|apikey|client_secret|secret|sessionid)"
        r"([\"']?\s*[=:]\s*[\"']?)([^\s;&,\"'}]+)", r"\1[REDACTED]", text,
    )
    return text[:limit] + ("...[truncated]" if len(text) > limit else "")

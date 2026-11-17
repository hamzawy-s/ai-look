from __future__ import annotations

import ipaddress
from typing import Iterable, Optional
from urllib.parse import urlparse


class ScopeEngine:
    """Production static scope gate (Phase 2 + Phase 3 remediation).

    Validates scheme / host / port / path / method. Rejects userinfo (including
    empty userinfo), port 0, path traversal and encoded traversal.
    Fail-closed: empty allowlist denies everything, any parse/authorization
    failure denies.
    """

    def __init__(
        self,
        allowed_hosts: Iterable[str] = (),
        allowed_schemes: Iterable[str] = ("https",),
        allowed_ports: Optional[Iterable[int]] = None,
        allowed_path_prefixes: Iterable[str] = ("/",),
        allowed_methods: Iterable[str] = ("GET", "POST"),
    ):
        self.allowed_hosts = {host.rstrip(".").lower() for host in allowed_hosts}
        self.allowed_schemes = {scheme.lower() for scheme in allowed_schemes}
        self.allowed_ports = set(allowed_ports) if allowed_ports is not None else None
        self.allowed_path_prefixes = tuple(allowed_path_prefixes)
        self.allowed_methods = {method.upper() for method in allowed_methods}

    def is_authorized(self, url: str, method: str = "GET") -> bool:
        try:
            parsed = urlparse(url)
            port = parsed.port
        except (ValueError, TypeError):
            return False

        if port is not None and port <= 0:
            return False

        if parsed.username or parsed.password:
            return False
        if "@" in (parsed.netloc or ""):
            return False
        if not parsed.scheme or parsed.scheme.lower() not in self.allowed_schemes:
            return False

        host = (parsed.hostname or "").rstrip(".").lower()
        if not host or host not in self.allowed_hosts:
            return False
        if method.upper() not in self.allowed_methods:
            return False

        if self.allowed_ports is not None:
            effective = (
                port
                if port is not None
                else (443 if parsed.scheme.lower() == "https" else 80)
            )
            if effective not in self.allowed_ports:
                return False

        return self._path_allowed(parsed.path or "/")

    def _path_allowed(self, path: str) -> bool:
        path = path or "/"
        lowered = path.lower()

        for token in (
            "/../", "/..",
            "/%2e%2e/", "/%2e%2e", "/%252e%252e/", "/%252e%252e",
            "/%2e.", "/.%2e", "%2e../",
        ):
            if token in lowered:
                return False

        for segment in path.split("/"):
            if segment in (".", ".."):
                return False

        if "//" in path or "%2f" in lowered:
            return False

        if "\\" in path or "%5c" in lowered:
            return False

        if "%252e" in lowered or "%252f" in lowered or "%255c" in lowered:
            return False

        for prefix in self.allowed_path_prefixes:
            if prefix == "/":
                return True
            normalized = prefix.rstrip("/")
            if path == normalized or path.startswith(normalized + "/"):
                return True
        return False

    def validate_ip(self, address: str, allow_private: bool = False) -> bool:
        """Validate an address according to the engine's network policy."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False

        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped

        if ip.is_multicast or ip.is_reserved or ip.is_unspecified or ip.is_link_local:
            return False

        if allow_private:
            if isinstance(ip, ipaddress.IPv4Address):
                return (
                    ip in ipaddress.IPv4Network("10.0.0.0/8")
                    or ip in ipaddress.IPv4Network("172.16.0.0/12")
                    or ip in ipaddress.IPv4Network("192.168.0.0/16")
                    or ip.is_loopback
                )
            return ip.is_loopback or ip in ipaddress.IPv6Network("fc00::/7")

        return bool(ip.is_global)
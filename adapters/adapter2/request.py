"""Shared asynchronous HTTP Request Engine (Phase 3 + Remediation).

Security model
--------------
* Every hop is authorized by the real Phase 2 ``ScopeEngine`` BEFORE any DNS
  resolution or connection. Missing scope / ``None`` / exception / ``False``
  all deny.
* Hostnames are resolved through an injectable resolver exactly once per hop.
  EVERY resolved address must pass IP policy; one unsafe address denies the
  whole request (no "pick the safe one" behaviour).
* The TCP connection is pinned to a validated IP by rewriting the request URL
  host. The original hostname is preserved for the HTTP ``Host`` header and,
  for HTTPS, for TLS SNI + certificate hostname verification via the
  ``sni_hostname`` request extension (verified present in httpcore 1.0.9:
  ``sni_hostname = request.extensions.get("sni_hostname", None)`` feeding
  ``"server_hostname": sni_hostname``).
* Redirects are never followed by HTTPX. When explicitly enabled they are
  processed manually and re-authorized hop by hop.
* Response bodies are streamed and bounded. Caps apply to BOTH the raw
  transfer bytes and the decoded body, so decompression bombs are bounded.
* ``trust_env=False`` always: environment proxies are never honoured.
* No AsyncClient injection: the engine owns its client; tests inject a
  transport instead.
* Proxy-Authorization is never sent and cookies are cleared after each
  request.
* Shutdown prevents a new client from being created by an in-flight request.

``ok`` semantics
----------------
``ok == True`` means the request completed according to engine policy.
Redirect policy stops return ``ok=False`` while preserving the received
status code and ``completed_exchange=True``.

Error taxonomy
--------------
scope, dns, timeout, tls, connection, transport, invalid_request,
redirect_scope_rejected, too_many_redirects, closed
plus one documented extension: ``unsafe_redirect_replay`` (307/308 carrying a
request body while ``replay_body_on_redirect`` is disabled).

``dns`` covers resolution failure, empty answers, AND resolved addresses that
are not permitted by IP policy.
"""
from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import ssl
import time
import zlib
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

__all__ = [
    "RequestConfig",
    "RequestResult",
    "RequestEngine",
    "Resolver",
    "default_resolver",
]

Resolver = Callable[[str, int], Awaitable[Sequence[str]]]

_SENSITIVE_REQUEST_HEADERS = frozenset(
    {"authorization", "cookie", "cookie2"}
)
_ALWAYS_STRIP_HEADERS = frozenset({"proxy-authorization"})
_SENSITIVE_RESPONSE_HEADERS = frozenset(
    {"set-cookie", "set-cookie2", "www-authenticate", "proxy-authenticate", "authorization"}
)
_REDACTED = "[REDACTED]"
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_ENGINE_CONTROLLED_HEADERS = frozenset({"host", "content-length", "transfer-encoding"})
_METHOD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*$")
_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_SUPPORTED_ENCODINGS = frozenset({"", "identity", "gzip", "deflate"})
_MIB = 1024 * 1024


class _InvalidRequest(Exception):
    pass


class _ResolutionError(Exception):
    pass


class _Closed(Exception):
    pass


@dataclass(frozen=True)
class RequestConfig:
    """Engine-owned security and resource limits.

    Per-request timeouts may only tighten these values, never loosen them.
    TLS verification is always enabled; ``tls_ca_bundle`` only ADDS trust.
    """

    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    write_timeout: float = 10.0
    pool_timeout: float = 5.0
    max_response_bytes: int = _MIB
    max_request_bytes: int = _MIB
    max_redirects: int = 5
    max_connections: int = 10
    max_keepalive_connections: int = 5
    follow_redirects: bool = False
    tls_ca_bundle: Optional[str] = None
    allow_private_ips: bool = False
    replay_body_on_redirect: bool = False

    def __post_init__(self) -> None:
        for name in ("connect_timeout", "read_timeout", "write_timeout", "pool_timeout"):
            value = getattr(self, name)
            if isinstance(value, bool):
                raise ValueError(f"{name} cannot be boolean")
            if not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be a number")
            if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
                raise ValueError(f"{name} must be finite")
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        for name in ("max_response_bytes", "max_request_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool):
                raise ValueError(f"{name} cannot be boolean")
            if not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        for name in ("max_redirects", "max_connections", "max_keepalive_connections"):
            value = getattr(self, name)
            if isinstance(value, bool):
                raise ValueError(f"{name} cannot be boolean")
            if not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
            if value < 0:
                raise ValueError(f"{name} must be non-negative")
        if self.max_keepalive_connections > self.max_connections:
            raise ValueError("max_keepalive_connections cannot exceed max_connections")


@dataclass
class RequestResult:
    """Structured outcome of one request (possibly across manual redirects)."""

    ok: bool
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    text: Optional[str] = None
    truncated: bool = False
    bytes_retained: int = 0
    content_encoding: Optional[str] = None
    body_is_decoded: bool = True
    http_version: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    rejected_redirect_url: Optional[str] = None
    error_category: Optional[str] = None
    error_message: Optional[str] = None
    pinned_ip: Optional[str] = None
    elapsed_ms: Optional[float] = None

    @property
    def completed_exchange(self) -> bool:
        """True when an HTTP response was received (status is meaningful)."""
        return self.status_code is not None


async def default_resolver(host: str, port: int) -> List[str]:
    """Production resolver using the operating system resolver."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, proto=0)
    return [info[4][0] for info in infos]


def _has_ssl_cause(exc: BaseException) -> bool:
    seen = set()
    current: Optional[BaseException] = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, ssl.SSLError):
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    message = str(exc).lower()
    return any(token in message for token in ("ssl", "tls", "certificate", "handshake"))


def _validate_method(method: Any) -> str:
    if not isinstance(method, str) or not _METHOD_RE.match(method):
        raise _InvalidRequest("invalid HTTP method")
    return method.upper()


def _parse_url(url: Any) -> Tuple[str, str, int]:
    """Return (scheme, host, port) after strict syntax validation."""
    if not isinstance(url, str) or not url:
        raise _InvalidRequest("url must be a non-empty string")
    if any(ch.isspace() for ch in url) or any(ord(ch) < 0x20 for ch in url):
        raise _InvalidRequest("url contains whitespace or control characters")
    try:
        parsed = urlparse(url)
        port = parsed.port
    except (ValueError, TypeError):
        raise _InvalidRequest("malformed url")
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise _InvalidRequest("unsupported scheme")
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        raise _InvalidRequest("userinfo in url is not allowed")
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        raise _InvalidRequest("url has no host")
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host, port


def _normalize_headers(headers: Any) -> Dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, dict):
        raise _InvalidRequest("headers must be a mapping")
    result: Dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not _TOKEN_RE.match(name):
            raise _InvalidRequest("invalid header name")
        if not isinstance(value, str):
            raise _InvalidRequest("invalid header value")
        if "\r" in value or "\n" in value or "\r" in name or "\n" in name:
            raise _InvalidRequest("header injection attempt")
        lower = name.lower()
        if lower in _ENGINE_CONTROLLED_HEADERS:
            continue  # engine controls Host and framing headers
        if lower in _ALWAYS_STRIP_HEADERS:
            continue
        result[lower] = value
    return result


def _validate_body(content: Any, cap: int) -> Optional[bytes]:
    if content is None:
        return None
    if isinstance(content, bytes):
        data = content
    elif isinstance(content, str):
        data = content.encode("utf-8")
    else:
        raise _InvalidRequest("content must be bytes or str")
    if len(data) > cap:
        raise _InvalidRequest("request body exceeds max_request_bytes")
    return data


def _host_header(scheme: str, host: str, port: int) -> str:
    default = 443 if scheme == "https" else 80
    if ":" in host:  # IPv6 literal
        return f"[{host}]" if port == default else f"[{host}]:{port}"
    return host if port == default else f"{host}:{port}"


def _origin(url: str) -> Tuple[str, str, int]:
    return _parse_url(url)


def _safe_url(url: str) -> str:
    """Record a redirect target without credentials, query or fragment."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").rstrip(".").lower()
        scheme = (parsed.scheme or "").lower()
        port = parsed.port
        netloc = _host_header(scheme, host, port or (443 if scheme == "https" else 80))
        return f"{scheme}://{netloc}{parsed.path or '/'}"
    except (ValueError, TypeError):
        return "[unparsable]"


class _DeflateDecoder:
    """zlib deflate with raw-deflate fallback on the first chunk."""

    def __init__(self) -> None:
        self._obj = zlib.decompressobj()
        self._produced = False

    def decompress(self, data: bytes, max_length: int) -> bytes:
        try:
            out = self._obj.decompress(data, max_length)
        except zlib.error:
            if self._produced:
                raise
            self._obj = zlib.decompressobj(-zlib.MAX_WBITS)
            out = self._obj.decompress(data, max_length)
        if out:
            self._produced = True
        return out

    def flush(self, max_length: int) -> bytes:
        try:
            return self._obj.flush(max_length)
        except zlib.error:
            return b""


def _make_decoder(encoding: str):
    if encoding in ("", "identity"):
        return None
    if encoding == "gzip":
        return zlib.decompressobj(16 + zlib.MAX_WBITS)
    if encoding == "deflate":
        return _DeflateDecoder()
    return None


class RequestEngine:
    """One reusable, scope-gated, DNS-pinned asynchronous HTTP engine."""

    def __init__(
        self,
        scope_engine: Any,
        *,
        config: Optional[RequestConfig] = None,
        resolver: Optional[Resolver] = None,
        _transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self._scope = scope_engine
        self._config = config or RequestConfig()
        self._resolver: Resolver = resolver or default_resolver
        self._transport = _transport
        self._client: Optional[httpx.AsyncClient] = None
        self._closed = False
        self._lock = asyncio.Lock()
        self._active: Set[asyncio.Task] = set()

    @property
    def config(self) -> RequestConfig:
        return self._config

    @property
    def closed(self) -> bool:
        return self._closed

    # ---------------- lifecycle ----------------

    async def _get_client(self) -> httpx.AsyncClient:
        """Return the single shared client; refuse after shutdown."""
        async with self._lock:
            if self._closed:
                raise _Closed("engine is closed")
            if self._client is None:
                verify: Any = True
                if self._config.tls_ca_bundle:
                    context = ssl.create_default_context(cafile=self._config.tls_ca_bundle)
                    context.check_hostname = True
                    context.verify_mode = ssl.CERT_REQUIRED
                    verify = context
                kwargs: Dict[str, Any] = {
                    "trust_env": False,
                    "follow_redirects": False,
                    "verify": verify,
                    "cookies": httpx.Cookies(),
                    "timeout": httpx.Timeout(
                        connect=self._config.connect_timeout,
                        read=self._config.read_timeout,
                        write=self._config.write_timeout,
                        pool=self._config.pool_timeout,
                    ),
                    "limits": httpx.Limits(
                        max_connections=self._config.max_connections,
                        max_keepalive_connections=self._config.max_keepalive_connections,
                    ),
                }
                if self._transport is not None:
                    kwargs["transport"] = self._transport
                self._client = httpx.AsyncClient(**kwargs)
            return self._client

    async def aclose(self) -> None:
        """Cancel active requests, await them, then close the client."""
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            client = self._client
            self._client = None
            current = asyncio.current_task()
            pending = [
                task
                for task in self._active
                if task is not current and not task.done()
            ]
            for task in pending:
                task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        if client is not None:
            await client.aclose()

    async def __aenter__(self) -> "RequestEngine":
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.aclose()

    # ---------------- policy helpers ----------------

    def _authorize(self, url: str, method: str) -> bool:
        if self._scope is None:
            return False
        try:
            return bool(self._scope.is_authorized(url, method))
        except Exception:
            return False

    def _ip_permitted(self, address: str) -> bool:
        if self._scope is None:
            return False
        try:
            return bool(
                self._scope.validate_ip(address, self._config.allow_private_ips)
            )
        except (AttributeError, TypeError, ValueError):
            return False

    async def _resolve_and_validate(self, host: str, port: int) -> List[str]:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            if not self._ip_permitted(str(literal)):
                raise _ResolutionError(f"address not permitted: {literal}")
            return [str(literal)]
        try:
            answers = await self._resolver(host, port)
        except Exception as exc:
            raise _ResolutionError(f"resolution failed: {type(exc).__name__}")
        if not answers:
            raise _ResolutionError("resolution returned no addresses")
        cleaned: List[str] = []
        for answer in answers:
            if not isinstance(answer, str):
                raise _ResolutionError("resolver returned a non-string address")
            if not self._ip_permitted(answer):
                raise _ResolutionError(f"resolved address not permitted: {answer}")
            cleaned.append(answer)
        return cleaned

    def _effective_timeout(self, timeout: Any) -> httpx.Timeout:
        cfg = self._config
        if timeout is None:
            return httpx.Timeout(
                connect=cfg.connect_timeout,
                read=cfg.read_timeout,
                write=cfg.write_timeout,
                pool=cfg.pool_timeout,
            )
        if isinstance(timeout, httpx.Timeout):
            supplied = {
                "connect": timeout.connect,
                "read": timeout.read,
                "write": timeout.write,
                "pool": timeout.pool,
            }
        elif isinstance(timeout, (int, float)) and timeout > 0:
            supplied = {k: float(timeout) for k in ("connect", "read", "write", "pool")}
        else:
            raise _InvalidRequest("invalid timeout")
        limits = {
            "connect": cfg.connect_timeout,
            "read": cfg.read_timeout,
            "write": cfg.write_timeout,
            "pool": cfg.pool_timeout,
        }
        merged = {
            key: min(float(value), limits[key]) if value is not None else limits[key]
            for key, value in supplied.items()
        }
        return httpx.Timeout(**merged)

    # ---------------- bounded streaming ----------------

    async def _read_bounded(
        self, response: httpx.Response
    ) -> Tuple[bytes, bool, Optional[str], bool]:
        cap = self._config.max_response_bytes
        limit = cap + 1
        encoding = (response.headers.get("content-encoding") or "").strip().lower()
        supported = encoding in _SUPPORTED_ENCODINGS
        decoder = _make_decoder(encoding) if supported else None
        out = bytearray()
        raw_read = 0
        stopped_early = False
        if getattr(response, "is_stream_consumed", False):
            data = response.content
            return data[:cap], len(data) > cap, (encoding or None), supported
        chunks = response.aiter_raw()
        async for chunk in chunks:
            if not chunk:
                continue
            take = min(len(chunk), limit - raw_read)
            if take <= 0:
                stopped_early = True
                break
            raw_read += take
            piece = chunk[:take]
            remaining = limit - len(out)
            if remaining > 0:
                if decoder is None:
                    out.extend(piece[:remaining])
                else:
                    out.extend(decoder.decompress(piece, remaining))
            if raw_read >= limit or len(out) >= limit:
                stopped_early = True
                break
        if decoder is not None and len(out) < limit:
            out.extend(decoder.flush(limit - len(out)))
        truncated = len(out) > cap or (stopped_early and raw_read >= limit)
        return bytes(out[:cap]), truncated, (encoding or None), supported

    @staticmethod
    def _decode_text(data: bytes, headers: Dict[str, str]) -> Optional[str]:
        charset = "utf-8"
        content_type = headers.get("content-type", "")
        for part in content_type.split(";"):
            part = part.strip()
            if part.lower().startswith("charset="):
                charset = part.split("=", 1)[1].strip().strip('"').strip("'") or "utf-8"
        try:
            return data.decode(charset)
        except (UnicodeDecodeError, LookupError):
            return None

    # ---------------- single pinned exchange ----------------

    async def _send_pinned(
        self,
        method: str,
        url: str,
        pinned_ip: str,
        headers: Dict[str, str],
        body: Optional[bytes],
        timeout: Any,
    ) -> RequestResult:
        scheme, host, port = _parse_url(url)
        try:
            client = await self._get_client()
        except _Closed:
            return RequestResult(
                ok=False, url=url, method=method,
                error_category="closed", error_message="engine is closed",
            )
        target = httpx.URL(url).copy_with(host=pinned_ip)
        outgoing = dict(headers)
        outgoing["host"] = _host_header(scheme, host, port)
        outgoing.setdefault("accept-encoding", "gzip, deflate")
        extensions: Dict[str, Any] = {}
        if scheme == "https":
            extensions["sni_hostname"] = host
        request = client.build_request(
            method,
            target,
            headers=outgoing,
            content=body,
            extensions=extensions,
            timeout=self._effective_timeout(timeout),
        )
        started = time.monotonic()
        try:
            response = await client.send(request, stream=True, follow_redirects=False)
        except httpx.TimeoutException as exc:
            return self._transport_failure(method, url, pinned_ip, "timeout", exc)
        except httpx.ConnectError as exc:
            category = "tls" if _has_ssl_cause(exc) else "connection"
            return self._transport_failure(method, url, pinned_ip, category, exc)
        except httpx.TransportError as exc:
            return self._transport_failure(method, url, pinned_ip, "transport", exc)
        except httpx.HTTPError as exc:
            return self._transport_failure(method, url, pinned_ip, "transport", exc)
        except RuntimeError as exc:
            category = "closed" if self._closed else "transport"
            return self._transport_failure(method, url, pinned_ip, category, exc)
        finally:
            client.cookies.clear()

        try:
            data, truncated, encoding, supported = await self._read_bounded(response)
        except httpx.TimeoutException as exc:
            return self._transport_failure(method, url, pinned_ip, "timeout", exc)
        except httpx.TransportError as exc:
            return self._transport_failure(method, url, pinned_ip, "transport", exc)
        except zlib.error:
            return self._transport_failure(
                method, url, pinned_ip, "transport", RuntimeError("content decoding failed")
            )
        finally:
            await response.aclose()
            client.cookies.clear()

        raw_headers = {k.lower(): v for k, v in response.headers.items()}
        safe_headers = {
            name: (_REDACTED if name in _SENSITIVE_RESPONSE_HEADERS else value)
            for name, value in raw_headers.items()
        }
        text = self._decode_text(data, raw_headers) if supported else None
        return RequestResult(
            ok=True,
            url=url,
            method=method,
            status_code=response.status_code,
            headers=safe_headers,
            body=data,
            text=text,
            truncated=truncated,
            bytes_retained=len(data),
            content_encoding=encoding,
            body_is_decoded=supported,
            http_version=response.http_version,
            pinned_ip=pinned_ip,
            elapsed_ms=(time.monotonic() - started) * 1000.0,
        )

    @staticmethod
    def _transport_failure(
        method: str, url: str, pinned_ip: Optional[str], category: str, exc: BaseException
    ) -> RequestResult:
        return RequestResult(
            ok=False,
            url=url,
            method=method,
            error_category=category,
            error_message=f"{type(exc).__name__}",
            pinned_ip=pinned_ip,
        )

    # ---------------- public entry point ----------------

    async def send_request(
        self,
        method: str = "GET",
        url: str = "",
        *,
        headers: Optional[Dict[str, str]] = None,
        content: Any = None,
        timeout: Any = None,
        follow_redirects: Optional[bool] = None,
    ) -> RequestResult:
        if self._closed:
            return RequestResult(
                ok=False, url=str(url), method=str(method),
                error_category="closed", error_message="engine is closed",
            )
        try:
            current_method = _validate_method(method)
            _parse_url(url)
            current_headers = _normalize_headers(headers)
            current_body = _validate_body(content, self._config.max_request_bytes)
            self._effective_timeout(timeout)
            if follow_redirects is not None and type(follow_redirects) is not bool:
                raise _InvalidRequest("follow_redirects must be a boolean or None")
        except _InvalidRequest as exc:
            return RequestResult(
                ok=False, url=str(url), method=str(method),
                error_category="invalid_request", error_message=str(exc),
            )

        task = asyncio.current_task()
        if task is not None:
            self._active.add(task)
        try:
            return await self._send_loop(
                url, current_method, current_headers, current_body, timeout,
                follow_redirects,
            )
        finally:
            if task is not None:
                self._active.discard(task)

    async def _send_loop(
        self,
        url: str,
        current_method: str,
        current_headers: Dict[str, str],
        current_body: Optional[bytes],
        timeout: Any,
        follow_redirects: Optional[bool] = None,
    ) -> RequestResult:
        should_follow_redirects = (
            self._config.follow_redirects if follow_redirects is None else follow_redirects
        )
        current_url = url
        chain: List[str] = []
        visited: Set[Tuple[str, str]] = set()
        last: Optional[RequestResult] = None

        for hop in range(self._config.max_redirects + 1):
            if not self._authorize(current_url, current_method):
                if last is not None:
                    last.error_category = "redirect_scope_rejected"
                    last.error_message = "redirect destination denied by scope"
                    last.rejected_redirect_url = _safe_url(current_url)
                    last.ok = False
                    last.redirect_chain = list(chain)
                    return last
                return RequestResult(
                    ok=False, url=current_url, method=current_method,
                    error_category="scope", error_message="scope authorization rejected",
                    redirect_chain=list(chain),
                )

            _, host, port = _parse_url(current_url)
            try:
                addresses = await self._resolve_and_validate(host, port)
            except _ResolutionError as exc:
                return RequestResult(
                    ok=False, url=current_url, method=current_method,
                    error_category="dns", error_message=str(exc),
                    redirect_chain=list(chain),
                )

            result = await self._send_pinned(
                current_method, current_url, addresses[0],
                current_headers, current_body, timeout,
            )
            result.redirect_chain = list(chain)
            if not result.ok:
                return result
            last = result

            if not should_follow_redirects:
                return result
            if result.status_code not in _REDIRECT_STATUSES:
                return result
            location = result.headers.get("location")
            if not location:
                return result

            try:
                next_url = urljoin(current_url, location)
                next_origin = _origin(next_url)
            except (ValueError, _InvalidRequest):
                result.error_category = "redirect_scope_rejected"
                result.error_message = "redirect target is malformed or unsupported"
                result.rejected_redirect_url = _safe_url(location)
                result.ok = False
                return result
            key = (current_method, current_url)
            if key in visited:
                result.error_category = "too_many_redirects"
                result.error_message = "redirect loop detected"
                result.ok = False
                return result
            visited.add(key)
            if hop >= self._config.max_redirects:
                result.error_category = "too_many_redirects"
                result.error_message = "maximum redirect count exceeded"
                result.ok = False
                return result

            chain.append(current_url)
            if _origin(current_url) != next_origin:
                current_headers = {
                    name: value
                    for name, value in current_headers.items()
                    if name not in _SENSITIVE_REQUEST_HEADERS
                }

            status = result.status_code
            if status in (301, 302, 303):
                if current_method not in ("GET", "HEAD"):
                    current_method = "GET"
                    current_body = None
                    current_headers = {
                        name: value
                        for name, value in current_headers.items()
                        if name not in ("content-type", "content-encoding")
                    }
            else:  # 307 / 308 preserve method and body
                if current_body is not None and not self._config.replay_body_on_redirect:
                    result.error_category = "unsafe_redirect_replay"
                    result.error_message = (
                        "307/308 redirect with a request body requires "
                        "replay_body_on_redirect=True"
                    )
                    result.ok = False
                    return result

            current_url = next_url

        return last if last is not None else RequestResult(
            ok=False, url=url, method=current_method,
            error_category="transport", error_message="request loop exhausted",
        )

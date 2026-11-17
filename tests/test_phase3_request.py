"""Phase 3 Request Engine tests.

Local-only: 127.0.0.1 / localhost, injected fake DNS resolvers, injected
transports, and local TLS mock servers. No public destinations, no external
DNS resolution, no proxies.
"""
from __future__ import annotations

import asyncio
import gzip
import ssl
import zlib
from typing import Dict, List, Optional

import httpx
import pytest

from adapters.adapter2.request import RequestConfig, RequestEngine
from adapters.adapter2.scope import ScopeEngine
from adapters.shared.request import AsyncRequestCore
from tests.tls_fixtures import CA_CERT, GOOD_CERT, GOOD_KEY, WRONG_CERT, WRONG_KEY

HOST = "testhost.local"
LOOPBACK = "127.0.0.1"
URL = f"https://{HOST}/api"


@pytest.mark.parametrize(
    "field,value",
    [
        ("connect_timeout", True),
        ("read_timeout", float("nan")),
        ("max_connections", True),
        ("max_keepalive_connections", 11),
    ],
)
def test_request_config_rejects_unsafe_limits(field, value):
    with pytest.raises(ValueError):
        RequestConfig(**{field: value})


class FakeResolver:
    """Injected resolver. Records calls; never touches real DNS."""

    def __init__(self, mapping: Dict[str, List[str]], raises: bool = False):
        self.mapping = mapping
        self.raises = raises
        self.calls: List[tuple] = []

    async def __call__(self, host: str, port: int) -> List[str]:
        self.calls.append((host, port))
        if self.raises:
            raise OSError("simulated resolution failure")
        return list(self.mapping.get(host, []))


class RecordingTransport(httpx.AsyncBaseTransport):
    """Captures pinned URL / Host / SNI, then returns a canned response."""

    def __init__(self, responder=None):
        self.requests: List[httpx.Request] = []
        self.responder = responder or (lambda req: httpx.Response(200, text="ok"))
        self.closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responder(request)

    async def aclose(self) -> None:
        self.closed = True


class RealRecordingTransport(httpx.AsyncBaseTransport):
    """Delegates to a REAL transport while recording the pinned destination."""

    def __init__(self, verify):
        self._inner = httpx.AsyncHTTPTransport(verify=verify)
        self.requests: List[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


def make_scope(**kw) -> ScopeEngine:
    kw.setdefault("allowed_hosts", {HOST})
    kw.setdefault("allowed_schemes", {"https", "http"})
    kw.setdefault("allowed_methods", {"GET", "POST", "PUT"})
    return ScopeEngine(**kw)


_DEFAULT_SCOPE = object()


def make_engine(scope=_DEFAULT_SCOPE, *, config=None, resolver=None, responder=None):
    transport = RecordingTransport(responder)
    engine = RequestEngine(
        make_scope() if scope is _DEFAULT_SCOPE else scope,
        config=config or RequestConfig(allow_private_ips=True),
        resolver=resolver or FakeResolver({HOST: [LOOPBACK]}),
        _transport=transport,
    )
    return engine, transport, engine


# ---------------- 13.1 authorization ----------------

@pytest.mark.parametrize(
    "scope_factory",
    [
        lambda: None,
        lambda: make_scope(allowed_hosts=set()),
        lambda: make_scope(allowed_hosts={"other.local"}),
    ],
)
async def test_scope_rejection_zero_dns_zero_transport(scope_factory):
    resolver = FakeResolver({HOST: [LOOPBACK]})
    engine, transport, client = make_engine(scope_factory(), resolver=resolver)
    result = await engine.send_request("GET", URL)
    assert result.ok is False
    assert result.error_category == "scope"
    assert resolver.calls == []
    assert transport.requests == []
    await client.aclose()


async def test_scope_exception_denies():
    class BoomScope:
        def is_authorized(self, url, method="GET"):
            raise RuntimeError("boom")

    resolver = FakeResolver({HOST: [LOOPBACK]})
    engine, transport, client = make_engine(BoomScope(), resolver=resolver)
    result = await engine.send_request("GET", URL)
    assert result.error_category == "scope"
    assert resolver.calls == [] and transport.requests == []
    await client.aclose()


async def test_disallowed_method_denied_by_scope():
    resolver = FakeResolver({HOST: [LOOPBACK]})
    engine, transport, client = make_engine(
        make_scope(allowed_methods={"GET"}), resolver=resolver
    )
    result = await engine.send_request("DELETE", URL)
    assert result.error_category == "scope"
    assert resolver.calls == [] and transport.requests == []
    await client.aclose()


@pytest.mark.parametrize(
    "bad_url",
    ["not a url", "ftp://testhost.local/x", "https://user:pw@testhost.local/x",
     "https://testhost.local:99999/x", ""],
)
async def test_invalid_request_syntax(bad_url):
    resolver = FakeResolver({HOST: [LOOPBACK]})
    engine, transport, client = make_engine(resolver=resolver)
    result = await engine.send_request("GET", bad_url)
    assert result.error_category == "invalid_request"
    assert resolver.calls == [] and transport.requests == []
    await client.aclose()


async def test_caller_cannot_override_host_header():
    engine, transport, client = make_engine()
    await engine.send_request("GET", URL, headers={"Host": "evil.local"})
    assert transport.requests[0].headers["host"] == HOST
    await client.aclose()


async def test_header_injection_rejected():
    engine, transport, client = make_engine()
    result = await engine.send_request("GET", URL, headers={"x-a": "1\r\nx-b: 2"})
    assert result.error_category == "invalid_request"
    assert transport.requests == []
    await client.aclose()


async def test_request_body_cap_enforced_before_send():
    resolver = FakeResolver({HOST: [LOOPBACK]})
    engine, transport, client = make_engine(
        config=RequestConfig(allow_private_ips=True, max_request_bytes=8), resolver=resolver
    )
    result = await engine.send_request("POST", URL, content=b"x" * 9)
    assert result.error_category == "invalid_request"
    assert transport.requests == []
    await client.aclose()


# ---------------- 13.2 DNS / IP policy ----------------

async def test_empty_resolver_result_is_dns_error():
    engine, transport, client = make_engine(resolver=FakeResolver({HOST: []}))
    result = await engine.send_request("GET", URL)
    assert result.error_category == "dns"
    assert transport.requests == []
    await client.aclose()


async def test_resolver_exception_is_dns_error():
    engine, transport, client = make_engine(resolver=FakeResolver({}, raises=True))
    result = await engine.send_request("GET", URL)
    assert result.error_category == "dns"
    assert transport.requests == []
    await client.aclose()


async def test_all_addresses_validated_mixed_rejected():
    engine, transport, client = make_engine(
        config=RequestConfig(allow_private_ips=False),
        resolver=FakeResolver({HOST: ["93.184.216.34", LOOPBACK]}),
    )
    result = await engine.send_request("GET", URL)
    assert result.error_category == "dns"
    assert transport.requests == []
    await client.aclose()


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1",
     "224.0.0.1", "240.0.0.1", "0.0.0.0", "::1", "::ffff:127.0.0.1"],
)
async def test_private_addresses_rejected_without_lab_mode(address):
    engine, transport, client = make_engine(
        config=RequestConfig(allow_private_ips=False),
        resolver=FakeResolver({HOST: [address]}),
    )
    result = await engine.send_request("GET", URL)
    assert result.error_category == "dns"
    assert transport.requests == []
    await client.aclose()


async def test_loopback_allowed_with_explicit_lab_mode():
    engine, transport, client = make_engine(
        config=RequestConfig(allow_private_ips=True),
        resolver=FakeResolver({HOST: [LOOPBACK]}),
    )
    result = await engine.send_request("GET", URL)
    assert result.ok is True and result.pinned_ip == LOOPBACK
    await client.aclose()


async def test_resolver_called_only_after_scope_approval():
    resolver = FakeResolver({HOST: [LOOPBACK]})
    engine, transport, client = make_engine(
        make_scope(allowed_hosts={"other.local"}), resolver=resolver
    )
    await engine.send_request("GET", URL)
    assert resolver.calls == []
    await client.aclose()


@pytest.mark.parametrize("literal", ["127.0.0.1", "[::1]"])
async def test_ip_literals_skip_dns(literal):
    resolver = FakeResolver({})
    host = literal.strip("[]")
    engine, transport, client = make_engine(
        make_scope(allowed_hosts={host}),
        config=RequestConfig(allow_private_ips=True),
        resolver=resolver,
    )
    result = await engine.send_request("GET", f"http://{literal}/api")
    if literal == "[::1]":
        assert result.error_category == "dns"
    else:
        assert result.ok is True
    assert resolver.calls == []
    await client.aclose()


# ---------------- 13.3 pinning: three separate facts (mock transport) ----------------

async def test_pinning_A_connection_reaches_validated_ip():
    resolver = FakeResolver({HOST: [LOOPBACK]})
    engine, transport, client = make_engine(resolver=resolver)
    await engine.send_request("GET", URL)
    # FACT A: transport-level destination is the validated IP, not the hostname.
    assert transport.requests[0].url.host == LOOPBACK
    assert len(resolver.calls) == 1
    await client.aclose()


async def test_pinning_B_host_header_preserves_original_hostname_and_port():
    engine, transport, client = make_engine()
    await engine.send_request("GET", f"https://{HOST}:8443/api")
    # FACT B: HTTP Host carries the original hostname and explicit port.
    assert transport.requests[0].headers["host"] == f"{HOST}:8443"
    await client.aclose()


async def test_pinning_C_sni_extension_uses_original_hostname():
    engine, transport, client = make_engine()
    await engine.send_request("GET", URL)
    # FACT C: TLS SNI / certificate hostname verification uses the original name.
    assert transport.requests[0].extensions.get("sni_hostname") == HOST
    await client.aclose()


async def test_rebinding_second_request_resolves_again():
    resolver = FakeResolver({HOST: [LOOPBACK]})
    engine, transport, client = make_engine(resolver=resolver)
    await engine.send_request("GET", URL)
    await engine.send_request("GET", URL)
    assert len(resolver.calls) == 2
    await client.aclose()


# ---------------- 13.3 real local HTTPS server + real TLS handshake ----------------

class LocalTLSServer:
    """Minimal local HTTPS server recording the received Host header."""

    def __init__(self, cert_pem: str, key_pem: str, tmp_path):
        self.cert_file = tmp_path / "server.pem"
        self.key_file = tmp_path / "server.key"
        self.cert_file.write_text(cert_pem, encoding="utf-8")
        self.key_file.write_text(key_pem, encoding="utf-8")
        self.ca_file = tmp_path / "ca.pem"
        self.ca_file.write_text(CA_CERT, encoding="utf-8")
        self.received_hosts: List[str] = []
        self.server: Optional[asyncio.AbstractServer] = None
        self.port: int = 0

    async def start(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(self.cert_file), str(self.key_file))
        self.server = await asyncio.start_server(self._handle, LOOPBACK, 0, ssl=ctx)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            for line in head.decode("latin-1").split("\r\n"):
                if line.lower().startswith("host:"):
                    self.received_hosts.append(line.split(":", 1)[1].strip())
            body = b"secure-ok"
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def stop(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()


@pytest.fixture
async def tls_server(tmp_path):
    server = LocalTLSServer(GOOD_CERT, GOOD_KEY, tmp_path)
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


def _client_context(ca_file) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(ca_file))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


async def test_real_tls_pinning_three_facts(tls_server):
    """Real socket + real TLS handshake. Three assertions kept separate."""
    resolver = FakeResolver({HOST: [LOOPBACK]})
    transport = RealRecordingTransport(verify=_client_context(tls_server.ca_file))
    engine = RequestEngine(
        make_scope(allowed_hosts={HOST}, allowed_schemes={"https"}),
        config=RequestConfig(allow_private_ips=True),
        resolver=resolver,
        _transport=transport,
    )
    url = f"https://{HOST}:{tls_server.port}/api"
    result = await engine.send_request("GET", url)

    assert result.ok is True, result.error_message
    assert result.status_code == 200
    assert result.body == b"secure-ok"

    # FACT A: the real connection went to the validated IP.
    assert transport.requests[0].url.host == LOOPBACK
    assert result.pinned_ip == LOOPBACK

    # FACT B: the server actually received the original hostname + port in Host.
    assert tls_server.received_hosts == [f"{HOST}:{tls_server.port}"]

    # FACT C: SNI used the original hostname, and the handshake succeeded against
    # a certificate whose SAN is ONLY testhost.local -> certificate hostname
    # verification used the original hostname, not the IP.
    assert transport.requests[0].extensions.get("sni_hostname") == HOST

    # If the engine had attempted real DNS for this fake hostname it would fail.
    assert resolver.calls == [(HOST, tls_server.port)]
    await engine.aclose()


async def test_real_tls_engine_owned_client_trusts_test_ca(tls_server):
    engine = RequestEngine(
        make_scope(allowed_hosts={HOST}, allowed_schemes={"https"}),
        config=RequestConfig(
            allow_private_ips=True, tls_ca_bundle=str(tls_server.ca_file)
        ),
        resolver=FakeResolver({HOST: [LOOPBACK]}),
    )
    try:
        result = await engine.send_request(
            "GET", f"https://{HOST}:{tls_server.port}/api"
        )
        assert result.ok is True and result.body == b"secure-ok"
    finally:
        await engine.aclose()


async def test_real_tls_wrong_hostname_certificate_is_rejected(tmp_path):
    server = LocalTLSServer(WRONG_CERT, WRONG_KEY, tmp_path)
    await server.start()
    try:
        engine = RequestEngine(
            make_scope(allowed_hosts={HOST}, allowed_schemes={"https"}),
            config=RequestConfig(
                allow_private_ips=True, tls_ca_bundle=str(server.ca_file)
            ),
            resolver=FakeResolver({HOST: [LOOPBACK]}),
        )
        try:
            result = await engine.send_request(
                "GET", f"https://{HOST}:{server.port}/api"
            )
            assert result.ok is False
            assert result.error_category == "tls"
        finally:
            await engine.aclose()
    finally:
        await server.stop()


# ---------------- 13.4 HTTP status semantics ----------------

@pytest.mark.parametrize("status", [200, 301, 302, 403, 406, 429, 500, 503])
async def test_http_statuses_are_completed_exchanges(status):
    engine, transport, client = make_engine(
        responder=lambda req: httpx.Response(status, headers={"x-probe": "1"}, text="body")
    )
    result = await engine.send_request("GET", URL)
    assert result.ok is True
    assert result.status_code == status
    assert result.error_category is None
    assert result.headers["x-probe"] == "1"
    await client.aclose()


async def test_sensitive_response_headers_redacted():
    engine, transport, client = make_engine(
        responder=lambda req: httpx.Response(
            200, headers={"set-cookie": "session=secret", "www-authenticate": "Basic realm=x"}
        )
    )
    result = await engine.send_request("GET", URL)
    assert result.headers["set-cookie"] == "[REDACTED]"
    assert result.headers["www-authenticate"] == "[REDACTED]"
    await client.aclose()


# ---------------- 13.5 bounded streaming ----------------

@pytest.mark.parametrize("size,expected_truncated", [(99, False), (100, False), (101, True)])
async def test_response_cap_boundary(size, expected_truncated):
    engine, transport, client = make_engine(
        config=RequestConfig(allow_private_ips=True, max_response_bytes=100),
        responder=lambda req: httpx.Response(200, content=b"a" * size),
    )
    result = await engine.send_request("GET", URL)
    assert result.ok is True
    assert result.bytes_retained == min(size, 100)
    assert result.truncated is expected_truncated
    await client.aclose()


@pytest.mark.parametrize("headers", [{}, {"content-length": "5"}])
async def test_missing_and_incorrect_content_length(headers):
    engine, transport, client = make_engine(
        config=RequestConfig(allow_private_ips=True, max_response_bytes=10),
        responder=lambda req: httpx.Response(200, content=b"b" * 50, headers=headers),
    )
    result = await engine.send_request("GET", URL)
    assert result.bytes_retained <= 10
    assert result.truncated is True
    await client.aclose()


async def test_chunked_response_is_bounded():
    class Chunked(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(20):
                yield b"c" * 16

    engine, transport, client = make_engine(
        config=RequestConfig(allow_private_ips=True, max_response_bytes=32),
        responder=lambda req: httpx.Response(200, stream=Chunked()),
    )
    result = await engine.send_request("GET", URL)
    assert result.bytes_retained <= 32
    assert result.truncated is True
    await client.aclose()


async def test_gzip_decompression_bomb_is_bounded():
    bomb = gzip.compress(b"a" * (5 * 1024 * 1024))
    engine, transport, client = make_engine(
        config=RequestConfig(allow_private_ips=True, max_response_bytes=1024),
        responder=lambda req: httpx.Response(
            200, stream=httpx.ByteStream(bomb), headers={"content-encoding": "gzip"}
        ),
    )
    result = await engine.send_request("GET", URL)
    assert result.ok is True
    assert result.bytes_retained <= 1024
    assert result.truncated is True
    await client.aclose()


async def test_deflate_body_decoded():
    payload = zlib.compress(b"hello deflate")
    engine, transport, client = make_engine(
        responder=lambda req: httpx.Response(
            200, stream=httpx.ByteStream(payload), headers={"content-encoding": "deflate"}
        )
    )
    result = await engine.send_request("GET", URL)
    assert result.body == b"hello deflate"
    assert result.text == "hello deflate"
    await client.aclose()


async def test_undecodable_bytes_yield_no_text():
    engine, transport, client = make_engine(
        responder=lambda req: httpx.Response(
            200, content=b"\xff\xfe\x00", headers={"content-type": "text/plain; charset=utf-8"}
        )
    )
    result = await engine.send_request("GET", URL)
    assert result.ok is True
    assert result.text is None
    await client.aclose()


# ---------------- 13.6 redirects ----------------

async def test_redirects_disabled_by_default():
    engine, transport, client = make_engine(
        responder=lambda req: httpx.Response(302, headers={"location": "/next"})
    )
    result = await engine.send_request("GET", URL)
    assert result.status_code == 302
    assert len(transport.requests) == 1
    await client.aclose()


async def test_same_origin_redirect_followed_when_enabled():
    def responder(req):
        if req.url.path == "/api":
            return httpx.Response(302, headers={"location": "/next"})
        return httpx.Response(200, text="final")

    engine, transport, client = make_engine(
        config=RequestConfig(allow_private_ips=True, follow_redirects=True),
        responder=responder,
    )
    result = await engine.send_request("GET", URL)
    assert result.status_code == 200 and result.text == "final"
    assert len(transport.requests) == 2
    await client.aclose()


async def test_unauthorized_redirect_preserves_3xx_and_resolves_nothing():
    resolver = FakeResolver({HOST: [LOOPBACK]})
    engine, transport, client = make_engine(
        config=RequestConfig(allow_private_ips=True, follow_redirects=True),
        resolver=resolver,
        responder=lambda req: httpx.Response(
            302, headers={"location": "https://evil.local/x?token=secret"}
        ),
    )
    result = await engine.send_request("GET", URL)
    assert result.status_code == 302
    assert result.error_category == "redirect_scope_rejected"
    assert result.rejected_redirect_url == "https://evil.local/x"
    assert len(transport.requests) == 1
    assert len(resolver.calls) == 1
    await client.aclose()


async def test_redirect_to_disallowed_port_rejected():
    engine, transport, client = make_engine(
        make_scope(allowed_hosts={HOST}, allowed_ports={443}),
        config=RequestConfig(allow_private_ips=True, follow_redirects=True),
        responder=lambda req: httpx.Response(
            302, headers={"location": f"https://{HOST}:9999/x"}
        ),
    )
    result = await engine.send_request("GET", URL)
    assert result.error_category == "redirect_scope_rejected"
    assert len(transport.requests) == 1
    await client.aclose()


async def test_redirect_to_unsupported_scheme_rejected():
    engine, transport, client = make_engine(
        config=RequestConfig(allow_private_ips=True, follow_redirects=True),
        responder=lambda req: httpx.Response(302, headers={"location": "ftp://x/y"}),
    )
    result = await engine.send_request("GET", URL)
    assert result.error_category == "redirect_scope_rejected"
    assert len(transport.requests) == 1
    await client.aclose()


async def test_redirect_loop_and_max_count():
    engine, transport, client = make_engine(
        config=RequestConfig(allow_private_ips=True, follow_redirects=True, max_redirects=3),
        responder=lambda req: httpx.Response(302, headers={"location": "/api"}),
    )
    result = await engine.send_request("GET", URL)
    assert result.error_category == "too_many_redirects"
    assert len(transport.requests) <= 4
    await client.aclose()


@pytest.mark.parametrize(
    "location,stripped",
    [
        (f"https://{HOST}/next", False),
        (f"https://{HOST}:8443/next", True),
        (f"http://{HOST}/next", True),
        ("https://other.local/next", True),
    ],
)
async def test_credential_stripping_on_origin_change(location, stripped):
    def responder(req):
        if req.url.path == "/api":
            return httpx.Response(302, headers={"location": location})
        return httpx.Response(200, text="final")

    engine, transport, client = make_engine(
        make_scope(allowed_hosts={HOST, "other.local"}),
        config=RequestConfig(allow_private_ips=True, follow_redirects=True),
        resolver=FakeResolver({HOST: [LOOPBACK], "other.local": [LOOPBACK]}),
        responder=responder,
    )
    result = await engine.send_request(
        "GET", URL,
        headers={"authorization": "Bearer t", "cookie": "s=1",
                 "proxy-authorization": "Basic p", "cookie2": "old=1"},
    )
    assert result.status_code == 200
    second = transport.requests[1].headers
    for name in ("authorization", "cookie", "cookie2"):
        assert (name in second) is (not stripped)
    assert "proxy-authorization" not in second
    await client.aclose()


async def test_303_converts_post_to_get_and_drops_body():
    def responder(req):
        if req.url.path == "/api":
            return httpx.Response(303, headers={"location": "/next"})
        return httpx.Response(200, text="final")

    engine, transport, client = make_engine(
        config=RequestConfig(allow_private_ips=True, follow_redirects=True),
        responder=responder,
    )
    await engine.send_request("POST", URL, content=b"payload")
    assert transport.requests[1].method == "GET"
    assert transport.requests[1].content == b""
    await client.aclose()


@pytest.mark.parametrize("status", [307, 308])
async def test_307_308_body_replay_requires_explicit_policy(status):
    engine, transport, client = make_engine(
        config=RequestConfig(allow_private_ips=True, follow_redirects=True),
        responder=lambda req: httpx.Response(status, headers={"location": "/next"}),
    )
    result = await engine.send_request("POST", URL, content=b"payload")
    assert result.status_code == status
    assert result.error_category == "unsafe_redirect_replay"
    assert len(transport.requests) == 1
    await client.aclose()


@pytest.mark.parametrize("status", [307, 308])
async def test_307_308_replay_allowed_with_explicit_policy(status):
    def responder(req):
        if req.url.path == "/api":
            return httpx.Response(status, headers={"location": "/next"})
        return httpx.Response(200, text="final")

    engine, transport, client = make_engine(
        config=RequestConfig(
            allow_private_ips=True, follow_redirects=True, replay_body_on_redirect=True
        ),
        responder=responder,
    )
    result = await engine.send_request("POST", URL, content=b"payload")
    assert result.status_code == 200
    assert transport.requests[1].method == "POST"
    assert transport.requests[1].content == b"payload"
    await client.aclose()


# ---------------- 13.7 transport errors ----------------

@pytest.mark.parametrize(
    "exc,expected",
    [
        (httpx.ConnectTimeout("t"), "timeout"),
        (httpx.ReadTimeout("t"), "timeout"),
        (httpx.WriteTimeout("t"), "timeout"),
        (httpx.PoolTimeout("t"), "timeout"),
        (httpx.ConnectError("refused"), "connection"),
        (httpx.RemoteProtocolError("bad"), "transport"),
    ],
)
async def test_transport_error_taxonomy(exc, expected):
    class Raising(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            raise exc

    transport = Raising()
    engine = RequestEngine(
        make_scope(), config=RequestConfig(allow_private_ips=True),
        resolver=FakeResolver({HOST: [LOOPBACK]}), _transport=transport,
    )
    result = await engine.send_request("GET", URL)
    assert result.ok is False and result.error_category == expected
    await engine.aclose()


async def test_tls_certificate_failure_category():
    class Raising(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            try:
                raise ssl.SSLCertVerificationError("certificate verify failed")
            except ssl.SSLCertVerificationError as cause:
                raise httpx.ConnectError("tls", request=request) from cause

    transport = Raising()
    engine = RequestEngine(
        make_scope(), config=RequestConfig(allow_private_ips=True),
        resolver=FakeResolver({HOST: [LOOPBACK]}), _transport=transport,
    )
    result = await engine.send_request("GET", URL)
    assert result.error_category == "tls"
    await engine.aclose()


# ---------------- 13.8 lifecycle ----------------

async def test_injected_transport_is_closed_with_engine():
    engine, transport, _ = make_engine()
    await engine._get_client()
    await engine.aclose()
    assert engine.closed is True
    assert transport.closed is True


async def test_owned_client_is_closed_and_aclose_idempotent():
    engine = RequestEngine(
        make_scope(), config=RequestConfig(allow_private_ips=True),
        resolver=FakeResolver({HOST: [LOOPBACK]}),
    )
    await engine._get_client()
    owned = engine._client
    await engine.aclose()
    await engine.aclose()
    assert owned.is_closed is True


async def test_request_after_close_returns_closed():
    engine, transport, client = make_engine()
    await engine.aclose()
    result = await engine.send_request("GET", URL)
    assert result.error_category == "closed"
    assert transport.requests == []
    await client.aclose()


async def test_get_client_after_close_raises_internally():
    from adapters.adapter2.request import _Closed

    engine, _, _ = make_engine()
    await engine.aclose()
    with pytest.raises(_Closed):
        await engine._get_client()


async def test_aclose_cancels_inflight_request():
    started = asyncio.Event()

    class SlowTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            started.set()
            await asyncio.sleep(10)
            return httpx.Response(200, text="late")

    engine = RequestEngine(
        make_scope(),
        config=RequestConfig(allow_private_ips=True),
        resolver=FakeResolver({HOST: [LOOPBACK]}),
        _transport=SlowTransport(),
    )
    task = asyncio.create_task(engine.send_request("GET", URL))
    await asyncio.wait_for(started.wait(), timeout=2.0)
    await engine.aclose()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert engine.closed is True
    assert engine._client is None


async def test_aclose_does_not_deadlock_from_request_task():
    engine, _, _ = make_engine()

    async def caller():
        await engine.send_request("GET", URL)
        await engine.aclose()

    await asyncio.wait_for(caller(), timeout=3.0)
    assert engine.closed is True


async def test_async_context_manager_closes():
    engine = RequestEngine(
        make_scope(), config=RequestConfig(allow_private_ips=True),
        resolver=FakeResolver({HOST: [LOOPBACK]}),
    )
    async with engine as ctx:
        assert ctx is engine
    assert engine.closed is True


async def test_concurrent_requests_share_one_client():
    engine = RequestEngine(
        make_scope(), config=RequestConfig(allow_private_ips=True),
        resolver=FakeResolver({HOST: [LOOPBACK]}),
    )
    clients = await asyncio.gather(*[engine._get_client() for _ in range(8)])
    assert len({id(c) for c in clients}) == 1
    await engine.aclose()


async def test_proxy_environment_is_ignored(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    engine = RequestEngine(
        make_scope(), config=RequestConfig(allow_private_ips=True),
        resolver=FakeResolver({HOST: [LOOPBACK]}),
    )
    client = await engine._get_client()
    assert client.trust_env is False
    await engine.aclose()


async def test_response_stream_closed_on_cancellation():
    closed = {"value": False}

    class SlowStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"a" * 8
            await asyncio.sleep(10)
            yield b"b" * 8

        async def aclose(self):
            closed["value"] = True

    engine, transport, client = make_engine(
        config=RequestConfig(allow_private_ips=True),
        responder=lambda req: httpx.Response(200, stream=SlowStream()),
    )
    task = asyncio.create_task(engine.send_request("GET", URL))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert closed["value"] is True
    await client.aclose()


# ---------------- shared facade convergence ----------------

async def test_facade_without_scope_denies():
    core = AsyncRequestCore(timeout=5.0)
    try:
        result = await core.request("GET", URL)
        assert result.ok is False
        assert result.error_category == "scope"
    finally:
        await core.close()


async def test_facade_with_scope_uses_engine():
    resolver = FakeResolver({HOST: [LOOPBACK]})
    transport = RecordingTransport()
    engine = RequestEngine(
        make_scope(), config=RequestConfig(allow_private_ips=True),
        resolver=resolver, _transport=transport,
    )
    core = AsyncRequestCore(engine=engine)
    try:
        result = await core.request("GET", URL)
        assert result.ok is True and result.status_code == 200
    finally:
        await core.close()
        assert engine.closed is False
        await engine.aclose()


async def test_facade_rejects_unknown_kwargs():
    core = AsyncRequestCore(timeout=5.0)
    try:
        with pytest.raises(TypeError):
            await core.request("GET", URL, verify=False)
    finally:
        await core.close()

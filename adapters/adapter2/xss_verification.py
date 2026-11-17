"""Isolated, browser-backed verification for reflected XSS candidates.

The browser never continues a request to its network stack. HTTP requests are
fulfilled from the existing scope-gated RequestEngine; redirects are checked
and stopped, and WebSockets are observed and blocked without opening a socket.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict

from core_engine import DeduplicationEngine

from .budget import BudgetExhaustedError, InvalidBudgetOriginError
from .framework import (
    AttemptStatus,
    BaseVulnerabilityAdapter,
    DetectionCandidate,
    Payload,
    PayloadType,
    TestRequest,
)
from .redaction import redact_url, sanitize_snippet
from .xss import XSSContext
from .sqli_verification import candidate_fingerprint


class XSSVerificationOutcome(str, Enum):
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_TESTED = "NOT_TESTED"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"


class XSSRequestRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: str
    method: str
    url: str
    scope_allowed: bool
    request_engine_used: bool = False
    budget_reserved: bool = False
    completed_exchange: bool = False
    status_code: Optional[int] = None
    pinned_ip: Optional[str] = None
    truncated: bool = False
    content_type: Optional[str] = None
    disposition: str
    reason: str


class XSSRedirectDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    source_url: str
    destination_url: str
    scope_allowed: bool
    followed: bool = False
    reason: str


class XSSVerificationReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    candidate_fingerprint: Optional[str]
    candidate_confidence: Optional[float] = None
    finding_fingerprint: str
    finding_type: str = "XSS"
    target: str
    parameter: str
    method: str = "GET"
    technique: str = "browser_execution_v1"
    strategy: str = "reflected_html_body_script_v1"
    response_content_type: Optional[str] = None
    context: str = XSSContext.UNKNOWN.value
    reflection_observed: bool = False
    payload_reflected_as_script: bool = False
    browser_started: bool = False
    isolated_context: bool = False
    headless: bool = False
    sandbox_enabled: bool = False
    network_controls_enforced: bool = False
    proxy_disabled: bool = False
    browser_dns_fallback_blocked: bool = False
    websockets_blocked: bool = False
    service_workers_disabled: bool = False
    downloads_disabled: bool = False
    browser_execution_observed: bool = False
    proof_token_sha256: Optional[str] = None
    proof_token_match: bool = False
    request_count: int = 0
    request_engine_exchange_count: int = 0
    budget_reservation_count: int = 0
    requests: Tuple[XSSRequestRecord, ...] = ()
    redirects: Tuple[XSSRedirectDecision, ...] = ()
    request_telemetry_complete: bool = False
    timed_out: bool = False
    truncated: bool = False
    cleanup_completed: bool = False
    human_review_required: bool = True
    outcome: XSSVerificationOutcome
    reason: str
    additional_verification_requirements: str = (
        "controlled JavaScript execution in the exact candidate response, "
        "with complete scoped request telemetry"
    )


_PARAMETER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z")
_MAX_BROWSER_REQUESTS = 32
_MAX_BROWSER_RESPONSE_BYTES = 1024 * 1024
_MAX_BROWSER_TOTAL_BYTES = 2 * 1024 * 1024
_REQUEST_TIMEOUT_SECONDS = 3.0
_NAVIGATION_TIMEOUT_MS = 8000
_BROWSER_LAUNCH_TIMEOUT_MS = 15000
_PLAYWRIGHT_START_TIMEOUT_SECONDS = 5.0
_CONTEXT_SETUP_TIMEOUT_SECONDS = 5.0
_BROWSER_CLEANUP_TIMEOUT_SECONDS = 3.0
_PROOF_PROPERTY = "__AI_LOOK_PHASE6_PROOF__"
_POLICY_BLOCK_COUNT_PROPERTY = "__AI_LOOK_PHASE6_POLICY_BLOCK_COUNT__"
_BROWSER_CSP = (
    "default-src http: https:; "
    "script-src http: https: 'unsafe-inline'; script-src-attr 'none'; "
    "connect-src http: https: ws: wss:; frame-src http: https:; "
    "worker-src http: https:; object-src 'none'; img-src http: https:; "
    "media-src http: https:; font-src http: https:; manifest-src http: https:; "
    "base-uri 'none'; form-action http: https:; "
    "sandbox allow-scripts allow-same-origin"
)
_SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "cookie2", "host",
    "content-length", "transfer-encoding", "connection", "keep-alive",
    "accept-encoding", "set-cookie", "set-cookie2", "www-authenticate",
    "proxy-authenticate", "content-encoding", "location",
})


def is_xss_finding_type(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return re.sub(r"[^A-Z0-9]", "", value.strip().upper()) in {
        "XSS", "CROSSSITESCRIPTING",
    }


def is_supported_xss_parameter_name(value: object) -> bool:
    return isinstance(value, str) and _PARAMETER.fullmatch(value) is not None


class _ProofScriptParser:
    """Recognize the exact unique proof script in a parsed HTML body."""

    def __init__(self, body: str, token: str):
        from html.parser import HTMLParser

        expected = f'window.{_PROOF_PROPERTY} = "{token}";'

        class Parser(HTMLParser):
            def __init__(self):
                super().__init__(convert_charrefs=False)
                self.stack: List[str] = []
                self.matches = 0

            def handle_starttag(self, tag, attrs):
                lowered = tag.lower()
                if lowered not in {
                    "area", "base", "br", "col", "embed", "hr", "img", "input",
                    "link", "meta", "param", "source", "track", "wbr",
                }:
                    self.stack.append(lowered)

            def handle_endtag(self, tag):
                lowered = tag.lower()
                for index in range(len(self.stack) - 1, -1, -1):
                    if self.stack[index] == lowered:
                        del self.stack[index:]
                        return

            def handle_data(self, data):
                if (
                    data.strip() == expected
                    and self.stack
                    and self.stack[-1] == "script"
                    and not any(tag in self.stack[:-1] for tag in (
                        "script", "style", "textarea", "title", "template", "svg", "math",
                    ))
                ):
                    self.matches += 1

        self.parser = Parser()
        self.valid = True
        try:
            self.parser.feed(body)
            self.parser.close()
        except (AssertionError, ValueError):
            self.valid = False

    @property
    def matched(self) -> bool:
        return self.valid and self.parser.matches == 1


def _content_type(headers: Dict[str, str]) -> str:
    value = next(
        (value for key, value in headers.items() if key.lower() == "content-type"),
        "",
    )
    return sanitize_snippet(value, 200)


def _valid_target(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        _ = parsed.port
    except (TypeError, ValueError):
        return False
    return bool(
        parsed.scheme.lower() in {"http", "https"}
        and parsed.hostname
        and parsed.netloc
        and "@" not in parsed.netloc
        and not parsed.query
        and not parsed.fragment
        and "?" not in url.split("#", 1)[0]
    )


def _finding_fingerprint(candidate: DetectionCandidate) -> str:
    return DeduplicationEngine().fingerprint_for(
        candidate.method,
        candidate.target,
        candidate.finding_type,
        candidate.parameter,
    )


def _redact_browser_url(url: str) -> str:
    """Keep URL structure while removing all browser-supplied query values."""
    try:
        parts = urlsplit(url)
        query = urlencode([(key, "[REDACTED]") for key, _ in parse_qsl(
            parts.query, keep_blank_values=True,
        )])
        return redact_url(urlunsplit((parts.scheme, parts.netloc, parts.path, query, "")))
    except (TypeError, ValueError):
        return "[INVALID_URL]"


def _candidate_screen(candidate: DetectionCandidate) -> Tuple[str, str, str]:
    """Return (content type, context, reason) for a Phase 6 safe-screen candidate."""
    if candidate.technique != "reflected-inert-marker-v1" or not candidate.evidence:
        return "", XSSContext.UNKNOWN.value, "candidate lacks Phase 6 inert-marker evidence"
    evidence = candidate.evidence[0]
    analysis = evidence.contextual_analysis or ""
    if "phase6_reflection_marker_v1" not in analysis:
        return "", XSSContext.UNKNOWN.value, "candidate evidence is not from the Phase 6 safe screen"
    content_match = re.search(r"(?:^|;\s*)response_content_type=([^;]*)", analysis)
    context_match = re.search(r"(?:^|;\s*)reflection_context=([A-Z_]+)", analysis)
    marker_hash_match = re.search(r"(?:^|;\s*)marker_sha256=([0-9a-f]{64})(?:;|$)", analysis)
    content_type = content_match.group(1) if content_match else ""
    context = context_match.group(1) if context_match else XSSContext.UNKNOWN.value
    marker = evidence.matched_signature
    if (
        re.fullmatch(r"AILOOKREFLECT[0-9a-f]{32}", marker)
        and evidence.response_body_snippet.count(marker) == 1
        and marker_hash_match is not None
        and marker_hash_match.group(1) == hashlib.sha256(marker.encode("ascii")).hexdigest()
        and evidence.request_method.upper() == "GET"
        and 200 <= evidence.response_status < 300
        and evidence.completed_exchange
        and not evidence.truncated
        and evidence.body_is_decoded
    ):
        return content_type, context, ""
    return content_type, context, "candidate reflection marker did not match the Phase 6 format"


class XSSVerifier(BaseVulnerabilityAdapter):
    """Verify one candidate with a single-use headless Chromium context."""

    def __init__(
        self,
        request_engine: Any,
        scope_engine: Any,
        *,
        budget_manager,
        scan_id: str,
        max_concurrent_requests: int = 3,
    ):
        if budget_manager is None:
            raise ValueError("XSSVerifier requires the scan's shared BudgetManager")
        if not isinstance(scan_id, str) or not scan_id.strip():
            raise ValueError("XSSVerifier requires a non-empty scan_id")
        super().__init__(
            request_engine,
            scope_engine,
            budget_manager=budget_manager,
            scan_id=scan_id,
            max_concurrent_requests=max_concurrent_requests,
        )
        self._records: List[XSSRequestRecord] = []
        self._redirects: List[XSSRedirectDecision] = []
        self._observed_http_requests: List[Tuple[str, str]] = []
        self._route_http_requests: List[Tuple[str, str]] = []
        self._route_tasks = set()
        self._route_error: Optional[str] = None
        self._timed_out = False
        self._truncated = False
        self._browser_started = False
        self._context_created = False
        self._cleanup_completed = False
        self._main_content_type: Optional[str] = None
        self._payload_reflected_as_script = False
        self._proof_token: Optional[str] = None
        self._probe_url: Optional[str] = None
        self._page = None
        self._context = None
        self._total_body_bytes = 0
        self._network_controls_enforced = False
        self._unsupported_browser_activity = False
        self._observed_policy_blocks = 0
        self._blocked_exchange = False
        self._unsupported_main_response = False
        self._incomplete_reasons: List[str] = []
        self._request_engine_exchange_count = 0
        self._attempted = False

    async def verify(self, candidate: DetectionCandidate) -> XSSVerificationReport:
        if self._attempted:
            raise RuntimeError("XSSVerifier instances are single-use; create one per candidate")
        self._attempted = True
        if not isinstance(candidate, DetectionCandidate):
            raise TypeError("candidate must be a DetectionCandidate")

        identity = candidate_fingerprint(candidate)
        finding_fp = _finding_fingerprint(candidate)
        base = dict(
            candidate_fingerprint=identity,
            candidate_confidence=candidate.confidence,
            finding_fingerprint=finding_fp,
            target=redact_url(candidate.target),
            parameter=candidate.parameter,
            context=XSSContext.UNKNOWN.value,
            reflection_observed=False,
            requests=(),
            redirects=(),
            request_count=0,
            request_engine_exchange_count=0,
            budget_reservation_count=0,
            request_telemetry_complete=False,
            cleanup_completed=True,
        )
        content_type, context, screen_reason = _candidate_screen(candidate)
        base["response_content_type"] = content_type or None
        base["context"] = context
        if screen_reason:
            return XSSVerificationReport(
                **base,
                outcome=XSSVerificationOutcome.NOT_TESTED,
                reason=screen_reason,
            )
        base["reflection_observed"] = True
        if (
            not _valid_target(candidate.target)
            or candidate.finding_type.strip().upper() not in {"XSS", "CROSS_SITE_SCRIPTING"}
            or candidate.method.upper() != "GET"
            or _PARAMETER.fullmatch(candidate.parameter) is None
        ):
            return XSSVerificationReport(
                **base,
                outcome=XSSVerificationOutcome.NOT_TESTED,
                reason="candidate identity is outside the supported Phase 6 target or input grammar",
            )
        if content_type.split(";", 1)[0].strip().lower() != "text/html":
            return XSSVerificationReport(
                **base,
                outcome=XSSVerificationOutcome.INCONCLUSIVE,
                reason="the reflected response content type is not text/html",
            )
        if context != XSSContext.HTML_BODY.value:
            return XSSVerificationReport(
                **base,
                outcome=XSSVerificationOutcome.INCONCLUSIVE,
                reason=f"reflected context {context} is not supported by Phase 6",
            )
        if not self._is_authorized(candidate.target, "GET"):
            return XSSVerificationReport(
                **base,
                outcome=XSSVerificationOutcome.BLOCKED,
                reason="candidate target was rejected by scope before browser startup",
            )
        if self.request_engine is None or not callable(
            getattr(self.request_engine, "send_request", None)
        ):
            return XSSVerificationReport(
                **base,
                outcome=XSSVerificationOutcome.BLOCKED,
                reason="RequestEngine is unavailable; browser verification fails closed",
            )

        self._proof_token = secrets.token_hex(24)
        payload = (
            f'<script>window.{_PROOF_PROPERTY} = "{self._proof_token}";</script>'
        )
        request = TestRequest(
            url=candidate.target,
            params={candidate.parameter: payload},
            payload=Payload(
                payload,
                PayloadType.REFLECTED,
                description="local-only Phase 6 execution proof",
                timeout_seconds=_REQUEST_TIMEOUT_SECONDS,
            ),
            follow_redirects=False,
            timeout_seconds=_REQUEST_TIMEOUT_SECONDS,
        )
        self._probe_url = request.build_url()

        try:
            await self._run_browser(candidate)
        except asyncio.TimeoutError:
            self._timed_out = True
            self._incomplete_reasons.append("browser verification exceeded its execution timeout")
        except ImportError:
            self._incomplete_reasons.append("Playwright is not installed")
        except OSError as exc:
            self._incomplete_reasons.append(f"browser runtime could not start: {type(exc).__name__}")
        except Exception as exc:
            # Browser routing errors are recorded and fail closed. The exception
            # class is retained; exception text can contain target data.
            self._route_error = self._route_error or type(exc).__name__
            self._incomplete_reasons.append(f"browser verification failed: {type(exc).__name__}")

        telemetry_complete = self._telemetry_complete()
        token_hash = hashlib.sha256(self._proof_token.encode("ascii")).hexdigest()
        proof_match = bool(getattr(self, "_observed_proof", None) == self._proof_token)
        execution_observed = getattr(self, "_observed_proof", None) is not None
        if not self._browser_started:
            reason = "; ".join(self._incomplete_reasons) or "browser did not start"
            outcome = XSSVerificationOutcome.BLOCKED
        elif not self._network_controls_enforced:
            reason = "required browser request controls were unavailable; verification failed closed"
            outcome = XSSVerificationOutcome.BLOCKED
        elif self._route_error:
            reason = f"browser network handler failed closed ({self._route_error})"
            outcome = XSSVerificationOutcome.INCONCLUSIVE
        elif not telemetry_complete:
            reason = (
                "browser request telemetry was incomplete; "
                f"observed_http={len(self._observed_http_requests)}, "
                f"routed_http={len(self._route_http_requests)}, "
                f"active_routes={len(self._route_tasks)}, "
                f"unsupported_activity={self._unsupported_browser_activity}"
            )
            outcome = XSSVerificationOutcome.INCONCLUSIVE
        elif self._redirects or self._blocked_exchange or self._unsupported_main_response:
            reason = "; ".join(self._incomplete_reasons) or "browser request was blocked by policy"
            outcome = XSSVerificationOutcome.INCONCLUSIVE
        elif self._timed_out:
            reason = "browser execution timed out; the candidate was not promoted"
            outcome = XSSVerificationOutcome.INCONCLUSIVE
        elif self._truncated:
            reason = "a browser response exceeded a configured size bound"
            outcome = XSSVerificationOutcome.INCONCLUSIVE
        elif proof_match and self._payload_reflected_as_script and self._cleanup_completed:
            reason = "the exact per-attempt proof token was observed after the reflected script appeared in the HTML response"
            outcome = XSSVerificationOutcome.VERIFIED
        elif proof_match and not self._payload_reflected_as_script:
            reason = "the proof token appeared without the controlled script in the main HTML response"
            outcome = XSSVerificationOutcome.INCONCLUSIVE
        elif not self._cleanup_completed:
            reason = "browser cleanup did not complete; the candidate was not promoted"
            outcome = XSSVerificationOutcome.INCONCLUSIVE
        else:
            reason = "; ".join(self._incomplete_reasons) or (
                "the controlled proof token did not execute in the browser"
            )
            outcome = XSSVerificationOutcome.NOT_VERIFIED

        base["response_content_type"] = self._main_content_type or content_type
        base.update({
            "payload_reflected_as_script": self._payload_reflected_as_script,
            "browser_started": self._browser_started,
            "isolated_context": self._context_created,
            "headless": self._browser_started,
            "sandbox_enabled": self._browser_started,
            "network_controls_enforced": self._network_controls_enforced,
            "proxy_disabled": self._network_controls_enforced,
            "browser_dns_fallback_blocked": self._network_controls_enforced,
            "websockets_blocked": self._network_controls_enforced,
            "service_workers_disabled": self._context_created,
            "downloads_disabled": self._context_created,
            "browser_execution_observed": execution_observed,
            "proof_token_sha256": token_hash,
            "proof_token_match": proof_match,
            "request_count": len(self._records),
            "request_engine_exchange_count": self._request_engine_exchange_count,
            "budget_reservation_count": sum(1 for item in self._records if item.budget_reserved),
            "requests": tuple(self._records),
            "redirects": tuple(self._redirects),
            "request_telemetry_complete": telemetry_complete,
            "timed_out": self._timed_out,
            "truncated": self._truncated,
            "cleanup_completed": self._cleanup_completed,
        })
        return XSSVerificationReport(
            **base,
            outcome=outcome,
            reason=reason,
        )

    async def _run_browser(self, candidate: DetectionCandidate) -> None:
        from playwright.async_api import Error as PlaywrightError
        from playwright.async_api import async_playwright

        playwright = await asyncio.wait_for(
            async_playwright().start(), timeout=_PLAYWRIGHT_START_TIMEOUT_SECONDS,
        )
        browser = None
        context = None
        try:
            browser = await playwright.chromium.launch(
                headless=True,
                chromium_sandbox=True,
                timeout=_BROWSER_LAUNCH_TIMEOUT_MS,
                args=[
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-sync",
                    "--disable-default-apps",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--no-proxy-server",
                    "--host-resolver-rules=MAP * ~NOTFOUND",
                    "--disable-quic",
                    "--disable-webrtc",
                ],
            )
            self._browser_started = True
            context = await asyncio.wait_for(
                browser.new_context(
                    accept_downloads=False,
                    service_workers="block",
                    storage_state=None,
                ),
                timeout=_CONTEXT_SETUP_TIMEOUT_SECONDS,
            )
            self._context = context
            self._context_created = True
            await asyncio.wait_for(
                context.route("**/*", self._route_request),
                timeout=_CONTEXT_SETUP_TIMEOUT_SECONDS,
            )
            if not callable(getattr(context, "route_web_socket", None)):
                raise RuntimeError("Playwright WebSocket routing is unavailable")
            await asyncio.wait_for(
                context.route_web_socket("**/*", self._block_websocket),
                timeout=_CONTEXT_SETUP_TIMEOUT_SECONDS,
            )
            await asyncio.wait_for(
                context.add_init_script(self._init_script()),
                timeout=_CONTEXT_SETUP_TIMEOUT_SECONDS,
            )
            context.on("request", self._observe_request)
            self._network_controls_enforced = True
            page = await asyncio.wait_for(
                context.new_page(), timeout=_CONTEXT_SETUP_TIMEOUT_SECONDS,
            )
            self._page = page
            context.on("page", self._observe_page)
            context.on("framenavigated", self._observe_frame_navigation)
            self._observed_proof = None
            page.set_default_timeout(2000)
            await page.goto(
                self._probe_url,
                wait_until="load",
                timeout=_NAVIGATION_TIMEOUT_MS,
            )
            self._observed_proof = await asyncio.wait_for(
                page.evaluate(f"() => window.{_PROOF_PROPERTY}"),
                timeout=2.0,
            )
            # Let browser-dispatched requests settle before taking the telemetry
            # snapshot. This waits on Playwright's network-idle signal, not a
            # fixed delay, and remains bounded for pages with ongoing activity.
            await page.wait_for_load_state("networkidle", timeout=1000)
            policy_blocks = await asyncio.wait_for(
                page.evaluate(f"() => globalThis.{_POLICY_BLOCK_COUNT_PROPERTY}()"),
                timeout=2.0,
            )
            if isinstance(policy_blocks, int) and policy_blocks > 0:
                self._observed_policy_blocks = min(policy_blocks, _MAX_BROWSER_REQUESTS)
                self._blocked_exchange = True
                for _ in range(self._observed_policy_blocks):
                    self._records.append(XSSRequestRecord(
                        kind="non-http", method="GET", url="[NON_HTTP_SCHEME]",
                        scope_allowed=False, disposition="blocked",
                        reason="browser policy denied a non-HTTP(S) resource before navigation",
                    ))
        except PlaywrightError as exc:
            if "timeout" in str(exc).lower():
                self._timed_out = True
            else:
                self._incomplete_reasons.append("Playwright reported a browser or navigation error")
        finally:
            cleanup_ok = True
            if context is not None:
                try:
                    await asyncio.wait_for(
                        context.close(), timeout=_BROWSER_CLEANUP_TIMEOUT_SECONDS
                    )
                except Exception:
                    cleanup_ok = False
            if browser is not None:
                try:
                    await asyncio.wait_for(
                        browser.close(), timeout=_BROWSER_CLEANUP_TIMEOUT_SECONDS
                    )
                except Exception:
                    cleanup_ok = False
            try:
                await asyncio.wait_for(
                    playwright.stop(), timeout=_BROWSER_CLEANUP_TIMEOUT_SECONDS,
                )
            except Exception:
                cleanup_ok = False
            pending = [task for task in self._route_tasks if not task.done()]
            if pending:
                for task in pending:
                    task.cancel()
                try:
                    results = await asyncio.wait_for(
                        asyncio.gather(*pending, return_exceptions=True),
                        timeout=_BROWSER_CLEANUP_TIMEOUT_SECONDS,
                    )
                    if any(isinstance(item, BaseException) for item in results):
                        cleanup_ok = False
                except asyncio.TimeoutError:
                    cleanup_ok = False
            self._cleanup_completed = cleanup_ok

    @staticmethod
    def _init_script() -> str:
        return r"""
        (() => {
          let policyBlockCount = 0;
          Object.defineProperty(globalThis, "__AI_LOOK_PHASE6_POLICY_BLOCK_COUNT__", {
            value: () => policyBlockCount,
            configurable: false,
            writable: false
          });
          globalThis.addEventListener("securitypolicyviolation", event => {
            const directive = event.effectiveDirective || "";
            if (["default-src", "frame-src", "worker-src", "object-src", "img-src",
                 "media-src", "font-src", "manifest-src"].includes(directive)) {
              policyBlockCount += 1;
            }
          });
          const blocked = function() {
            throw new DOMException("blocked by AI Look verification policy", "NotAllowedError");
          };
          for (const name of ["RTCPeerConnection", "webkitRTCPeerConnection", "WebTransport"]) {
            try { Object.defineProperty(globalThis, name, {value: undefined, configurable: false, writable: false}); }
            catch (_) { /* a missing browser API is already blocked */ }
          }
          try { Object.defineProperty(globalThis, "open", {value: () => null, configurable: false, writable: false}); }
          catch (_) { /* popup requests are also blocked by the context router */ }
          try { Object.defineProperty(navigator, "sendBeacon", {value: blocked, configurable: false, writable: false}); }
          catch (_) { /* HTTP requests still pass through the context router */ }
        })();
        """

    def _observe_request(self, request) -> None:
        parsed = urlsplit(request.url)
        if parsed.scheme.lower() in {"http", "https"}:
            self._observed_http_requests.append((request.url, request.method.upper()))

    def _observe_page(self, page) -> None:
        if page is self._page:
            return
        self._unsupported_browser_activity = True
        self._incomplete_reasons.append("a popup was created and blocked")
        self._track_cleanup_task(asyncio.create_task(page.close()))

    def _observe_frame_navigation(self, frame) -> None:
        parsed = urlsplit(frame.url)
        if parsed.scheme.lower() in {"http", "https"}:
            return
        if (
            parsed.scheme.lower() == "about"
            and frame.url == "about:blank"
            and self._page is not None
            and frame == self._page.main_frame
        ):
            return
        self._unsupported_browser_activity = True
        self._blocked_exchange = True
        self._incomplete_reasons.append("a non-HTTP(S) frame navigation was blocked by closing the page")
        scheme = parsed.scheme.lower() or "unknown"
        self._records.append(XSSRequestRecord(
            kind="non-http", method="GET", url=f"[{scheme.upper()}_NAVIGATION]",
            scope_allowed=False, disposition="blocked",
            reason="non-HTTP(S) frame navigation was detected; browser page was closed",
        ))
        if self._page is not None:
            self._track_cleanup_task(asyncio.create_task(self._page.close()))

    def _track_cleanup_task(self, task: asyncio.Task) -> None:
        self._route_tasks.add(task)
        task.add_done_callback(self._cleanup_task_finished)

    def _cleanup_task_finished(self, task: asyncio.Task) -> None:
        self._route_tasks.discard(task)
        if task.cancelled():
            return
        try:
            error = task.exception()
        except Exception as exc:
            error = exc
        if error is not None:
            self._route_error = self._route_error or type(error).__name__
            self._incomplete_reasons.append("a browser page cleanup task failed")

    async def _block_websocket(self, websocket) -> None:
        url = websocket.url
        parsed = urlsplit(url)
        mapped_scheme = {"ws": "http", "wss": "https"}.get(parsed.scheme.lower())
        mapped = urlunsplit((mapped_scheme or "", parsed.netloc, parsed.path, parsed.query, ""))
        allowed = bool(mapped_scheme and self._is_authorized(mapped, "GET"))
        reserved = False
        reason = "WebSockets are disabled and no upstream connection is opened"
        if allowed:
            try:
                self.budget_manager.reserve(self.scan_id, mapped)
                reserved = True
            except (BudgetExhaustedError, InvalidBudgetOriginError):
                reason = "WebSocket attempt was blocked by the shared request budget"
                self._incomplete_reasons.append(reason)
                self._blocked_exchange = True
        else:
            reason = "WebSocket attempt was rejected by scope"
        self._records.append(XSSRequestRecord(
            kind="websocket",
            method="GET",
            url=_redact_browser_url(url),
            scope_allowed=allowed,
            request_engine_used=False,
            budget_reserved=reserved,
            disposition="blocked",
            reason=reason,
        ))

    async def _route_request(self, route) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._route_tasks.add(task)
        request = route.request
        url = request.url
        method = request.method.upper()
        record_index = len(self._records)
        request_scope_allowed = False
        budget_reserved = False
        request_engine_used = False
        routed_response = None
        try:
            parsed = urlsplit(url)
            if parsed.scheme.lower() not in {"http", "https"}:
                self._records.append(XSSRequestRecord(
                    kind="non-http", method=method, url=_redact_browser_url(url),
                    scope_allowed=False, disposition="blocked",
                    reason="only HTTP and HTTPS are accepted by the browser request policy",
                ))
                await route.abort("blockedbyclient")
                return
            key = (url, method)
            self._route_http_requests.append(key)
            if method != "GET":
                await self._account_and_block(route, "only GET is supported by Phase 6")
                return
            if self._page is not None and request.frame.page is not self._page:
                await self._account_and_block(route, "popup page requests are blocked")
                return
            if (
                request.is_navigation_request()
                and request.frame == self._page.main_frame
                and url != self._probe_url
            ):
                await self._account_and_block(route, "additional top-level navigation is blocked")
                return
            if len(self._route_http_requests) > _MAX_BROWSER_REQUESTS:
                self._blocked_exchange = True
                self._incomplete_reasons.append("browser request count exceeded the per-verification limit")
                await self._account_and_block(route, "per-verification browser request limit reached")
                return

            headers = {}
            accept = request.headers.get("accept")
            if accept:
                headers["accept"] = accept[:256]
            request_model = TestRequest(
                url=url,
                method="GET",
                headers=headers,
                follow_redirects=False,
                timeout_seconds=_REQUEST_TIMEOUT_SECONDS,
            )
            attempt = await self.execute_request(request_model)
            request_scope_allowed = attempt.status != AttemptStatus.SCOPE_REJECTED
            budget_reserved = attempt.status not in {
                AttemptStatus.SCOPE_REJECTED,
                AttemptStatus.BUDGET_EXHAUSTED,
            }
            request_engine_used = budget_reserved
            routed_response = attempt.response
            if request_engine_used:
                self._request_engine_exchange_count += 1
            response = routed_response
            if not attempt.ok or response is None:
                self._records.append(XSSRequestRecord(
                    kind="http",
                    method=method,
                    url=_redact_browser_url(url),
                    scope_allowed=request_scope_allowed,
                    request_engine_used=request_engine_used,
                    budget_reserved=budget_reserved,
                    completed_exchange=bool(response and response.completed_exchange),
                    status_code=response.status_code if response else None,
                    pinned_ip=response.pinned_ip if response else None,
                    truncated=bool(response and response.truncated),
                    content_type=_content_type(response.headers) if response else None,
                    disposition="blocked",
                    reason=attempt.reason,
                ))
                if attempt.status in {
                    AttemptStatus.BUDGET_EXHAUSTED,
                    AttemptStatus.INCONCLUSIVE,
                    AttemptStatus.TIMEOUT,
                    AttemptStatus.TRANSPORT_ERROR,
                }:
                    self._incomplete_reasons.append(
                        f"RequestEngine attempt ended with {attempt.status.value}"
                    )
                    self._blocked_exchange = True
                if attempt.status == AttemptStatus.WAF_BLOCKED:
                    self._incomplete_reasons.append(attempt.reason)
                    self._blocked_exchange = True
                if response and response.truncated:
                    self._truncated = True
                if response and response.error_category == "dns":
                    self._incomplete_reasons.append("RequestEngine DNS validation failed closed")
                    self._blocked_exchange = True
                if attempt.status == AttemptStatus.TIMEOUT:
                    self._timed_out = True
                await route.abort("blockedbyclient")
                return

            ctype = _content_type(response.headers)
            if 300 <= response.status_code < 400:
                location = next(
                    (value for key, value in response.headers.items()
                     if key.lower() == "location"),
                    "",
                )
                destination = urljoin(url, location) if location else ""
                redirect_allowed = bool(destination and self._is_authorized(destination, "GET"))
                self._redirects.append(XSSRedirectDecision(
                    source_url=_redact_browser_url(url),
                    destination_url=_redact_browser_url(destination) if destination else "[MISSING_LOCATION]",
                    scope_allowed=redirect_allowed,
                    followed=False,
                    reason=(
                        "redirect destination was checked and not followed by Chromium"
                        if redirect_allowed
                        else "redirect destination was rejected by scope or missing"
                    ),
                ))
                self._blocked_exchange = True
                self._records.append(XSSRequestRecord(
                    kind="http", method=method, url=_redact_browser_url(url),
                    scope_allowed=True, request_engine_used=True,
                    budget_reserved=budget_reserved, completed_exchange=True,
                    status_code=response.status_code, pinned_ip=response.pinned_ip,
                    content_type=ctype, disposition="redirect-blocked",
                    reason="redirects are checked and stopped; browser auto-follow is disabled",
                ))
                self._incomplete_reasons.append("redirect response was not followed")
                await route.abort("blockedbyclient")
                return

            is_main_navigation = url == self._probe_url and request.is_navigation_request()
            if is_main_navigation:
                self._main_content_type = ctype
                if ctype.split(";", 1)[0].strip().lower() != "text/html":
                    self._unsupported_main_response = True
                    self._incomplete_reasons.append("browser main response was not text/html")
                    self._records.append(XSSRequestRecord(
                        kind="http", method=method, url=_redact_browser_url(url),
                        scope_allowed=True, request_engine_used=True,
                        budget_reserved=budget_reserved, completed_exchange=response.completed_exchange,
                        status_code=response.status_code, pinned_ip=response.pinned_ip,
                        content_type=ctype, disposition="unsupported-content-type",
                        reason="only text/html is supported as the browser document",
                    ))
                    await route.abort("blockedbyclient")
                    return
                if not 200 <= response.status_code < 300:
                    self._unsupported_main_response = True
                    self._incomplete_reasons.append("browser main response was not a successful 2xx exchange")
                    self._records.append(XSSRequestRecord(
                        kind="http", method=method, url=_redact_browser_url(url),
                        scope_allowed=True, request_engine_used=True,
                        budget_reserved=budget_reserved, completed_exchange=response.completed_exchange,
                        status_code=response.status_code, pinned_ip=response.pinned_ip,
                        content_type=ctype, disposition="unsupported-status",
                        reason="only 2xx HTML documents are supported",
                    ))
                    await route.abort("blockedbyclient")
                    return
                script_parser = _ProofScriptParser(response.body, self._proof_token or "")
                self._payload_reflected_as_script = script_parser.matched

            if response.truncated or not response.body_is_decoded:
                self._truncated = response.truncated
                self._incomplete_reasons.append("response was truncated or not decoded by RequestEngine")
                self._records.append(XSSRequestRecord(
                    kind="http", method=method, url=_redact_browser_url(url),
                    scope_allowed=True, request_engine_used=True,
                    budget_reserved=budget_reserved, completed_exchange=response.completed_exchange,
                    status_code=response.status_code, pinned_ip=response.pinned_ip,
                    truncated=response.truncated, content_type=ctype,
                    disposition="blocked", reason="incomplete RequestEngine response",
                ))
                await route.abort("blockedbyclient")
                return

            body_bytes = response.body.encode("utf-8")
            if (
                len(body_bytes) > _MAX_BROWSER_RESPONSE_BYTES
                or self._total_body_bytes + len(body_bytes) > _MAX_BROWSER_TOTAL_BYTES
            ):
                self._truncated = True
                self._incomplete_reasons.append("browser response size bound reached")
                self._records.append(XSSRequestRecord(
                    kind="http", method=method, url=_redact_browser_url(url),
                    scope_allowed=True, request_engine_used=True,
                    budget_reserved=budget_reserved, completed_exchange=response.completed_exchange,
                    status_code=response.status_code, pinned_ip=response.pinned_ip,
                    truncated=True, content_type=ctype, disposition="blocked",
                    reason="response exceeded the Phase 6 browser size limit",
                ))
                await route.abort("blockedbyclient")
                return
            self._total_body_bytes += len(body_bytes)

            disposition = next(
                (value for key, value in response.headers.items()
                 if key.lower() == "content-disposition"),
                "",
            )
            if "attachment" in disposition.lower():
                self._blocked_exchange = True
                self._records.append(XSSRequestRecord(
                    kind="http", method=method, url=_redact_browser_url(url),
                    scope_allowed=True, request_engine_used=True,
                    budget_reserved=budget_reserved, completed_exchange=response.completed_exchange,
                    status_code=response.status_code, pinned_ip=response.pinned_ip,
                    content_type=ctype, disposition="download-blocked",
                    reason="download response was blocked",
                ))
                await route.abort("blockedbyclient")
                return

            media_type = ctype.split(";", 1)[0].strip().lower()
            if not (
                media_type.startswith("text/")
                or media_type in {"application/javascript", "application/x-javascript", "application/json"}
            ):
                self._blocked_exchange = True
                self._incomplete_reasons.append("a non-text browser resource was blocked")
                self._records.append(XSSRequestRecord(
                    kind="http", method=method, url=_redact_browser_url(url),
                    scope_allowed=True, request_engine_used=True,
                    budget_reserved=budget_reserved, completed_exchange=response.completed_exchange,
                    status_code=response.status_code, pinned_ip=response.pinned_ip,
                    content_type=ctype, disposition="unsupported-resource",
                    reason="Phase 6 serves only bounded decoded text resources",
                ))
                await route.abort("blockedbyclient")
                return

            if len(self._route_http_requests) > _MAX_BROWSER_REQUESTS:
                self._incomplete_reasons.append("browser request count exceeded the per-verification limit")
                self._blocked_exchange = True
                await route.abort("blockedbyclient")
                return

            safe_headers = {
                key.lower(): value
                for key, value in response.headers.items()
                if key.lower() not in _SENSITIVE_HEADERS
                and "\r" not in value and "\n" not in value
            }
            if media_type == "text/html":
                existing_csp = safe_headers.get("content-security-policy", "").strip()
                safe_headers["content-security-policy"] = (
                    f"{existing_csp}, {_BROWSER_CSP}" if existing_csp else _BROWSER_CSP
                )
            self._records.append(XSSRequestRecord(
                kind="http", method=method, url=_redact_browser_url(url),
                scope_allowed=True, request_engine_used=True,
                budget_reserved=budget_reserved, completed_exchange=response.completed_exchange,
                status_code=response.status_code, pinned_ip=response.pinned_ip,
                content_type=ctype, disposition="fulfilled-by-request-engine",
                reason="response was fulfilled from the shared RequestEngine",
            ))
            await route.fulfill(
                status=response.status_code,
                headers=safe_headers,
                body=response.body,
            )
        except Exception as exc:
            self._route_error = type(exc).__name__
            self._incomplete_reasons.append("browser route failed closed")
            self._blocked_exchange = True
            if len(self._records) == record_index:
                self._records.append(XSSRequestRecord(
                    kind="http", method=method, url=_redact_browser_url(url),
                    scope_allowed=request_scope_allowed,
                    request_engine_used=request_engine_used,
                    budget_reserved=budget_reserved,
                    completed_exchange=bool(routed_response and routed_response.completed_exchange),
                    status_code=routed_response.status_code if routed_response else None,
                    pinned_ip=routed_response.pinned_ip if routed_response else None,
                    truncated=bool(routed_response and routed_response.truncated),
                    content_type=_content_type(routed_response.headers) if routed_response else None,
                    disposition="blocked",
                    reason=f"route handler failed closed ({type(exc).__name__})",
                ))
            try:
                await route.abort("blockedbyclient")
            except Exception:
                self._incomplete_reasons.append("route abort cleanup failed")
        finally:
            if task is not None:
                self._route_tasks.discard(task)

    async def _account_and_block(self, route, reason: str) -> None:
        request = route.request
        url = request.url
        method = request.method.upper()
        scope_allowed = self._is_authorized(url, method)
        reserved = False
        if scope_allowed:
            try:
                self.budget_manager.reserve(self.scan_id, url)
                reserved = True
            except (BudgetExhaustedError, InvalidBudgetOriginError):
                reason = "request was blocked by the shared budget"
        self._records.append(XSSRequestRecord(
            kind="http", method=method, url=_redact_browser_url(url),
            scope_allowed=scope_allowed, request_engine_used=False,
            budget_reserved=reserved, disposition="blocked", reason=reason,
        ))
        if not scope_allowed:
            self._incomplete_reasons.append("out-of-scope browser request was denied before network access")
        await route.abort("blockedbyclient")

    def _telemetry_complete(self) -> bool:
        observed = sorted(self._observed_http_requests)
        routed = sorted(self._route_http_requests)
        return bool(
            self._context_created
            and self._cleanup_completed
            and observed == routed
            and not self._route_tasks
            and self._route_error is None
            and not self._unsupported_browser_activity
        )

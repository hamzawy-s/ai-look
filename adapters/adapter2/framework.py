"""Base framework for vulnerability detection adapters."""
from __future__ import annotations

import asyncio
import hashlib
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core_engine import Finding, FindingStatus, ObservationStatus, Severity
from .budget import BudgetExhaustedError, BudgetManager, InvalidBudgetOriginError
from .models import TestOutcome
from .redaction import redact_headers, redact_url, sanitize_snippet

class PayloadType(Enum):
    """Payload classification for test planning."""

    BENIGN = "BENIGN"
    TIME_BASED = "TIME_BASED"
    ERROR_BASED = "ERROR_BASED"
    BOOLEAN_BASED = "BOOLEAN_BASED"
    REFLECTED = "REFLECTED"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    CALLBACK = "CALLBACK"
    UNION_BASED = "UNION_BASED"


@dataclass
class Payload:
    """A test payload with metadata."""

    value: str
    payload_type: PayloadType
    signature: Optional[str] = None
    expected_status: Optional[int] = None
    timeout_seconds: float = 10.0
    description: str = ""

    def __post_init__(self):
        if not self.value:
            raise ValueError("Payload value cannot be empty")


@dataclass
class TestRequest:
    """A structured test request."""

    __test__ = False

    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    params: Any = field(default_factory=dict)
    body: Optional[str] = None
    timeout_seconds: float = 10.0
    payload: Optional[Payload] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    follow_redirects: Optional[bool] = None

    def __post_init__(self):
        if self.follow_redirects is not None and type(self.follow_redirects) is not bool:
            raise ValueError("follow_redirects must be a boolean or None")

    def build_url(self) -> str:
        parsed = urlparse(self.url)
        params = list(self.params.items()) if isinstance(self.params, dict) else list(self.params or [])
        query = urlencode(
            parse_qsl(parsed.query, keep_blank_values=True) + params,
            doseq=True,
        )
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, query, ""))

    @property
    def fingerprint(self) -> str:
        params = list(self.params.items()) if isinstance(self.params, dict) else list(self.params or [])
        components = [
            self.method.upper(),
            self.build_url(),
            urlencode(sorted(params, key=lambda item: (str(item[0]), str(item[1])))),
            self.body or "",
            str(self.follow_redirects),
        ]
        return hashlib.sha256("|".join(components).encode()).hexdigest()[:16]


@dataclass
class TestResponse:
    """A structured test response."""

    __test__ = False

    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed_ms: float
    payload: Optional[Payload] = None
    truncated: bool = False
    body_is_decoded: bool = True
    error_category: Optional[str] = None
    completed_exchange: bool = True
    pinned_ip: Optional[str] = None
    final_url: Optional[str] = None
    request_url: Optional[str] = None
    error_message: Optional[str] = None

    @property
    def is_error(self) -> bool:
        return self.status_code >= 400

    @property
    def is_error_status(self) -> bool:
        return self.is_error

    @classmethod
    def from_request_result(cls, result, request):
        def bool_field(name, default):
            value = getattr(result, name, default)
            return value if type(value) is bool else default

        text = getattr(result, "text", None)
        if not isinstance(text, str):
            raw_body = getattr(result, "body", b"")
            text = raw_body.decode("utf-8", errors="replace") if isinstance(raw_body, bytes) else (raw_body if isinstance(raw_body, str) else "")
        return cls(
            int(getattr(result, "status_code", 0) or 0),
            redact_headers(getattr(result, "headers", {}) or {}),
            text,
            float(getattr(result, "elapsed_ms", 0.0) or 0.0),
            request.payload,
            bool_field("truncated", False),
            bool_field("body_is_decoded", True),
            getattr(result, "error_category", None),
            bool_field("completed_exchange", True),
            getattr(result, "pinned_ip", None) if isinstance(getattr(result, "pinned_ip", None), str) else None,
            getattr(result, "url", None) if isinstance(getattr(result, "url", None), str) else None,
            request.build_url(),
            getattr(result, "error_message", None),
        )

    @property
    def is_timeout(self) -> bool:
        return self.elapsed_ms >= (
            self.payload.timeout_seconds * 1000 if self.payload else 10000
        )


@dataclass(frozen=True)
class Evidence:
    """Verifiable evidence for a finding."""

    request_url: str
    request_method: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: int
    response_headers: Dict[str, str]
    response_body_snippet: str
    matched_signature: str
    elapsed_ms: float
    completed_exchange: bool = True
    truncated: bool = False
    body_is_decoded: bool = True
    pinned_ip: Optional[str] = None
    contextual_analysis: Optional[str] = None

    @classmethod
    def from_request_response(
        cls,
        request: TestRequest,
        response: TestResponse,
        signature: str,
        max_body_length: int = 500,
    ) -> "Evidence":
        item = cls.from_attempt(request, response, signature)
        return cls(**{**item.__dict__,
                      "response_body_snippet": sanitize_snippet(response.body, max_body_length)})

    @classmethod
    def from_attempt(cls, request, response, signature):
        final_url = response.final_url if isinstance(response.final_url, str) else request.build_url()
        return cls(
            request_url=redact_url(final_url),
            request_method=request.method.upper(),
            request_headers=redact_headers(request.headers),
            request_body= sanitize_snippet(request.body, 500),
            response_status=response.status_code,
            response_headers=redact_headers(response.headers),
            response_body_snippet=sanitize_snippet(response.body, 800),
            matched_signature=signature,
            elapsed_ms=response.elapsed_ms,
            completed_exchange=response.completed_exchange,
            truncated=response.truncated,
            body_is_decoded=response.body_is_decoded,
            pinned_ip=response.pinned_ip,
        )


def response_is_analyzable(response: TestResponse) -> bool:
    return response.completed_exchange and not response.truncated and response.body_is_decoded


def response_indicates_waf_block(response: TestResponse) -> bool:
    if response.status_code not in {403, 406, 429, 503} or not response_is_analyzable(response):
        return False
    material = " ".join([response.body.lower(), " ".join(
        f"{key}:{value}" for key, value in response.headers.items()
    ).lower()])
    return any(marker in material for marker in (
        "cloudflare", "cf-ray", "aws waf", "x-amzn-waf", "modsecurity",
        "incapsula", "sucuri website firewall", "azure application gateway",
        "akamai reference #", "cloud armor",
    ))


@dataclass(frozen=True)
class DetectionCandidate:
    """Unconfirmed observation, intentionally independent from Core Finding."""
    finding_type: str
    target: str
    parameter: str
    method: str
    technique: str
    confidence: float
    evidence: Sequence[Evidence]
    reason: str
    verification_required: str

    def __post_init__(self):
        if not self.finding_type or not self.target or not self.technique:
            raise ValueError("candidate identity fields must be non-empty")
        if isinstance(self.confidence, bool) or not 0.0 <= self.confidence <= 1.0:
            raise ValueError("candidate confidence must be in [0.0, 1.0]")
        if not self.reason or not self.verification_required:
            raise ValueError("candidate reason and verification requirement are required")
        object.__setattr__(self, "target", redact_url(self.target))
        object.__setattr__(self, "evidence", tuple(self.evidence))


class AttemptStatus(Enum):
    OK = "OK"
    SCOPE_REJECTED = "SCOPE_REJECTED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    TRANSPORT_ERROR = "TRANSPORT_ERROR"
    TIMEOUT = "TIMEOUT"
    WAF_BLOCKED = "WAF_BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class RequestOutcome:
    status: AttemptStatus
    response: Optional[TestResponse]
    error_category: Optional[str]
    reason: str
    coverage_outcome: TestOutcome

    @property
    def ok(self) -> bool:
        return self.status == AttemptStatus.OK and self.response is not None


@dataclass
class AdapterScanResult:
    findings: List[Finding]
    candidates: List[DetectionCandidate]
    coverage_outcome: TestOutcome
    reason: str
    evidence_count: int = 0


def aggregate_coverage(outcomes):
    if not outcomes:
        return TestOutcome.SKIPPED
    for candidate in (TestOutcome.PRESENT, TestOutcome.INCONCLUSIVE,
                      TestOutcome.BLOCKED, TestOutcome.ERROR, TestOutcome.SKIPPED):
        if candidate in outcomes:
            return candidate
    return TestOutcome.ABSENT


class BaseVulnerabilityAdapter:
    """Base class for all vulnerability adapters."""

    def __init__(
        self,
        request_engine: Any,
        scope_engine: Any,
        max_requests_per_target: int = 100,
        max_concurrent_requests: int = 3,
        *,
        budget_manager: Optional[BudgetManager] = None,
        scan_id: Optional[str] = None,
        waf_classifier: Optional[Any] = None,
    ):
        self.request_engine = request_engine
        self.scope_engine = scope_engine
        self.budget_manager = budget_manager or BudgetManager(max_requests_per_target)
        self.scan_id = scan_id or str(uuid.uuid4())
        self.max_concurrent_requests = max_concurrent_requests
        self._scan_problem_outcome: Optional[TestOutcome] = None
        self._scan_problem_reason: Optional[str] = None
        self.waf_classifier = waf_classifier

    def _is_authorized(self, url: str, method: str = "GET") -> bool:
        if self.scope_engine is None:
            return False
        try:
            return bool(self.scope_engine.is_authorized(url, method))
        except Exception:
            return False

    def _capture_attempt(self, outcome: RequestOutcome) -> None:
        if outcome.coverage_outcome in {
            TestOutcome.BLOCKED, TestOutcome.ERROR, TestOutcome.SKIPPED,
            TestOutcome.INCONCLUSIVE,
        }:
            self._scan_problem_outcome = outcome.coverage_outcome
            self._scan_problem_reason = outcome.reason

    async def execute_request(self, request: TestRequest) -> RequestOutcome:
        """The sole adapter request path: scope, engine, shared gate, budget, transport, mapping."""
        try:
            actual_url = request.build_url()
        except Exception as exc:
            return RequestOutcome(AttemptStatus.TRANSPORT_ERROR, None, "invalid_request",
                                  str(exc)[:300], TestOutcome.ERROR)
        if not self._is_authorized(actual_url, request.method):
            return RequestOutcome(AttemptStatus.SCOPE_REJECTED, None, "scope",
                                  "scope rejection before network access",
                                  TestOutcome.SKIPPED)
        if self.request_engine is None or not callable(getattr(self.request_engine, "send_request", None)):
            return RequestOutcome(
                AttemptStatus.TRANSPORT_ERROR,
                None,
                "invalid_request",
                "request engine unavailable",
                TestOutcome.ERROR,
            )
        try:
            semaphore = self.budget_manager.semaphore_for(
                self.scan_id, self.max_concurrent_requests
            )
            async with semaphore:
                self.budget_manager.reserve(self.scan_id, actual_url)
                send_options = {
                    "method": request.method,
                    "url": actual_url,
                    "headers": request.headers,
                    "content": request.body,
                    "timeout": request.timeout_seconds,
                }
                if request.follow_redirects is not None:
                    send_options["follow_redirects"] = request.follow_redirects
                result = await self.request_engine.send_request(
                    **send_options,
                )
            response = TestResponse.from_request_result(result, request)
        except InvalidBudgetOriginError as exc:
            return RequestOutcome(AttemptStatus.TRANSPORT_ERROR, None, "invalid_origin",
                                  str(exc), TestOutcome.ERROR)
        except BudgetExhaustedError as exc:
            return RequestOutcome(AttemptStatus.BUDGET_EXHAUSTED, None, "budget",
                                  str(exc), TestOutcome.SKIPPED)
        except TimeoutError:
            return RequestOutcome(AttemptStatus.TIMEOUT, None, "timeout",
                                  "request timed out", TestOutcome.INCONCLUSIVE)
        except Exception as exc:
            category = getattr(exc, "error_category", None) or "transport"
            timeout = isinstance(exc, TimeoutError) or category == "timeout"
            return RequestOutcome(AttemptStatus.TIMEOUT if timeout else AttemptStatus.TRANSPORT_ERROR,
                                  None, category, str(exc)[:300],
                                  TestOutcome.INCONCLUSIVE if timeout else TestOutcome.ERROR)
        if response_indicates_waf_block(response):
            return RequestOutcome(AttemptStatus.WAF_BLOCKED, response, None,
                                  "request was blocked by a likely WAF signature", TestOutcome.BLOCKED)
        if response.error_category in {"scope", "redirect_scope_rejected"}:
            return RequestOutcome(AttemptStatus.SCOPE_REJECTED, response,
                                  response.error_category, "request rejected by scope", TestOutcome.SKIPPED)
        if response.error_category and not response.completed_exchange:
            status = AttemptStatus.TIMEOUT if response.error_category == "timeout" else AttemptStatus.TRANSPORT_ERROR
            outcome = TestOutcome.INCONCLUSIVE if status == AttemptStatus.TIMEOUT else TestOutcome.ERROR
            return RequestOutcome(status, response, response.error_category,
                                  response.error_message or "request transport failed", outcome)
        if not response.completed_exchange:
            return RequestOutcome(AttemptStatus.INCONCLUSIVE, response,
                                  response.error_category,
                                  "incomplete HTTP exchange", TestOutcome.INCONCLUSIVE)
        if response.truncated or not response.body_is_decoded:
            return RequestOutcome(AttemptStatus.INCONCLUSIVE, response, None,
                                  "response body is incomplete or undecodable", TestOutcome.INCONCLUSIVE)
        return RequestOutcome(AttemptStatus.OK, response, response.error_category,
                              "completed HTTP exchange", TestOutcome.INCONCLUSIVE)

    def make_finding(self, *, finding_type, target, parameter, method,
                     severity, confidence, evidence, remediation):
        if not evidence:
            raise ValueError("cannot create finding without evidence")
        return Finding(
            type=finding_type, target=target, parameter=parameter, method=method,
            severity=severity, confidence=confidence,
            source=self.__class__.__name__, status=FindingStatus.OPEN,
            evidence=[
                f"{item.request_method} {item.request_url} -> HTTP {item.response_status}; "
                f"signature={item.matched_signature}; elapsed_ms={item.elapsed_ms:.0f}"
                for item in evidence[:8]
            ],
            observation_status=ObservationStatus.PRESENT,
            remediation=remediation,
        )

    def make_candidate(
        self, *, finding_type, target, parameter, method, technique,
        confidence, evidence, reason,
    ) -> DetectionCandidate:
        if not evidence:
            raise ValueError("cannot create candidate without evidence")
        return DetectionCandidate(
            finding_type=finding_type, target=target, parameter=parameter,
            method=method, technique=technique, confidence=confidence,
            evidence=tuple(evidence), reason=reason,
            verification_required=("browser execution instrumentation" if "xss" in finding_type.lower()
                                  else "verified vulnerable database behavior"),
        )

    async def scan(self, target_url: str, parameters: List[str]) -> List[Finding]:
        raise NotImplementedError("Subclass must implement scan()")

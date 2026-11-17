"""Deterministic, bounded Boolean verification for SQLi detection candidates.

Only conservative query values are eligible. Every HTTP exchange uses the
existing adapter request path so scope, budget, concurrency, and redirect
policy remain owned by the Phase 2–4 infrastructure.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, quote_plus, urlsplit

from .budget import BudgetManager, InvalidBudgetOriginError
from .framework import (
    AttemptStatus,
    BaseVulnerabilityAdapter,
    DetectionCandidate,
    Payload,
    PayloadType,
    TestRequest,
    TestResponse,
    response_is_analyzable,
)
from .redaction import redact_url
from .models import TestOutcome


class SQLiVerificationOutcome(str, Enum):
    VERIFIED = "VERIFIED"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_TESTED = "NOT_TESTED"
    ERROR = "ERROR"


class SQLiValueContext(str, Enum):
    NUMERIC = "NUMERIC"
    SINGLE_QUOTED_STRING = "SINGLE_QUOTED_STRING"


@dataclass(frozen=True)
class SQLiVerificationSample:
    group: str
    repetition: int
    request_fingerprint: str
    request_url: str
    status_code: Optional[int]
    response_sha256: Optional[str]
    response_length: int
    completed_exchange: bool
    truncated: bool
    body_is_decoded: bool
    empty: bool
    reflection_neutralized: bool
    control_reflection_detected: bool
    error_category: Optional[str] = None


@dataclass(frozen=True)
class SQLiVerificationReport:
    candidate_fingerprint: Optional[str]
    finding_fingerprint: str
    finding_type: str
    target: str
    parameter: str
    method: str
    technique: str
    strategy: str
    context: Optional[str]
    outcome: SQLiVerificationOutcome
    planned_repetitions: int
    completed_repetitions: int
    request_count: int
    baseline_matches_true: Optional[bool]
    false_differs: Optional[bool]
    samples: Tuple[SQLiVerificationSample, ...]
    reason: str
    additional_verification_requirements: str


_NUMERIC_LITERAL = re.compile(r"-?(?:0|[1-9][0-9]{0,8})(?:\.[0-9]{1,6})?\Z")
_STRING_LITERAL = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_PARAMETER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z")
_AMBIGUOUS_SQL_WORDS = frozenset({
    "AND", "AS", "BETWEEN", "CASE", "CAST", "CREATE", "DELETE", "DROP",
    "ELSE", "END", "EXEC", "FALSE", "FROM", "IN", "INSERT", "IS", "JOIN",
    "LIKE", "NOT", "NULL", "OR", "SELECT", "THEN", "TRUE", "UNION", "UPDATE",
    "WHEN", "WHERE",
})
_REPETITIONS = 3
_REQUIRED_REQUESTS = _REPETITIONS * 3
_STRATEGY = "repeated_boolean_differential_v1"


def is_sqli_finding_type(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return re.sub(r"[^A-Z0-9]", "", value.strip().upper()) in {
        "SQLI", "SQLINJECTION",
    }


def classify_original_value(value: object) -> Optional[SQLiValueContext]:
    """Accept only bounded numeric or conservative bare string values.

    The supported string grammar intentionally excludes whitespace, quotes,
    operators, separators, comments, and punctuation. Values are application
    inputs; the verifier adds the SQL quote only for the declared string
    context.
    """
    if not isinstance(value, str):
        return None
    if _NUMERIC_LITERAL.fullmatch(value):
        return SQLiValueContext.NUMERIC
    if (_STRING_LITERAL.fullmatch(value)
            and value.upper() not in _AMBIGUOUS_SQL_WORDS):
        return SQLiValueContext.SINGLE_QUOTED_STRING
    return None


def is_supported_parameter_name(parameter: object) -> bool:
    return isinstance(parameter, str) and _PARAMETER.fullmatch(parameter) is not None


def candidate_fingerprint(candidate: DetectionCandidate) -> str:
    """Stable identity for one candidate, including its detection technique."""
    identity = (
        candidate.finding_type.strip().upper(),
        candidate.target,
        candidate.parameter,
        candidate.method.upper(),
        candidate.technique,
    )
    payload = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class SQLiVerifier(BaseVulnerabilityAdapter):
    """Verify SQLi candidates with three repeated, interleaved Boolean controls."""

    def __init__(
        self,
        request_engine,
        scope_engine,
        *,
        budget_manager: BudgetManager,
        scan_id: str,
        max_concurrent_requests: int = 3,
    ):
        if budget_manager is None:
            raise ValueError("SQLiVerifier requires the scan's shared BudgetManager")
        if not isinstance(scan_id, str) or not scan_id.strip():
            raise ValueError("SQLiVerifier requires the scan's non-empty scan_id")
        super().__init__(
            request_engine,
            scope_engine,
            budget_manager=budget_manager,
            scan_id=scan_id,
            max_concurrent_requests=max_concurrent_requests,
        )

    @staticmethod
    def _finding_fingerprint(candidate: DetectionCandidate) -> str:
        from core_engine import DeduplicationEngine

        return DeduplicationEngine().fingerprint_for(
            candidate.method,
            candidate.target,
            candidate.finding_type,
            candidate.parameter,
        )

    @staticmethod
    def _request_value(value: str, context: SQLiValueContext, group: str) -> str:
        if group == "baseline":
            return value
        if context == SQLiValueContext.NUMERIC:
            condition = "1=1" if group == "true" else "1=2"
            return f"{value} AND {condition}"
        condition = "'1'='1" if group == "true" else "'1'='2"
        return f"{value}' AND {condition}"

    @staticmethod
    def _normalize(
        body: str,
        request_value: str,
        original_value: Optional[str] = None,
    ) -> Tuple[str, bool]:
        """Normalize whitespace and mask exact input reflection only.

        No timestamps, identifiers, or arbitrary response regions are removed.
        Consequently, dynamic content causes instability instead of being
        normalized into a manufactured positive result.
        """
        normalized = body.replace("\r\n", "\n").replace("\r", "\n")
        variants = {
            request_value,
            html.escape(request_value, quote=True),
            request_value.replace("'", "&#39;").replace('"', "&quot;"),
            quote(request_value, safe=""),
            quote_plus(request_value, safe=""),
            quote(request_value, safe="").lower(),
            quote_plus(request_value, safe="").lower(),
        }
        if original_value:
            variants.update({
                original_value,
                html.escape(original_value, quote=True),
                original_value.replace("'", "&#39;").replace('"', "&quot;"),
                quote(original_value, safe=""),
                quote_plus(original_value, safe=""),
                quote(original_value, safe="").lower(),
                quote_plus(original_value, safe="").lower(),
            })
        neutralized = False
        for variant in sorted((item for item in variants if item), key=len, reverse=True):
            if variant in normalized:
                normalized = normalized.replace(variant, "<INPUT>")
                neutralized = True
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized, neutralized

    @staticmethod
    def _contains_control_reflection(
        body: str,
        context: SQLiValueContext,
        group: str,
    ) -> bool:
        if group == "baseline":
            return False
        condition = (
            "1=1" if group == "true" else "1=2"
        ) if context == SQLiValueContext.NUMERIC else (
            "'1'='1" if group == "true" else "'1'='2"
        )
        expressions = {f"AND {condition}", condition}
        variants = set()
        for expression in expressions:
            variants.update({
                expression,
                html.escape(expression, quote=True),
                expression.replace("'", "&#39;").replace('"', "&quot;"),
                quote(expression, safe=""),
                quote_plus(expression, safe=""),
                quote(expression, safe="").lower(),
                quote_plus(expression, safe="").lower(),
            })
        normalized_body = re.sub(r"\s+", " ", body).casefold()
        return any(
            re.sub(r"\s+", " ", variant).casefold() in normalized_body
            for variant in variants if variant
        )

    @staticmethod
    def _is_supported_target(target: str) -> bool:
        try:
            parts = urlsplit(target)
            _ = parts.port
        except (TypeError, ValueError):
            return False
        return bool(
            parts.scheme.lower() in {"http", "https"}
            and parts.hostname
            and not parts.username
            and not parts.password
            and not parts.query
            and not parts.fragment
        )

    @staticmethod
    def _completed_repetitions(samples: List[SQLiVerificationSample]) -> int:
        groups = {"baseline": set(), "true": set(), "false": set()}
        for sample in samples:
            if sample.completed_exchange:
                groups[sample.group].add(sample.repetition)
        return len(groups["baseline"] & groups["true"] & groups["false"])

    def _report(
        self,
        candidate: DetectionCandidate,
        *,
        context: Optional[SQLiValueContext],
        outcome: SQLiVerificationOutcome,
        reason: str,
        request_count: int = 0,
        samples: Optional[List[SQLiVerificationSample]] = None,
        baseline_matches_true: Optional[bool] = None,
        false_differs: Optional[bool] = None,
    ) -> SQLiVerificationReport:
        samples = samples or []
        return SQLiVerificationReport(
            candidate_fingerprint=candidate_fingerprint(candidate),
            finding_fingerprint=self._finding_fingerprint(candidate),
            finding_type=candidate.finding_type,
            target=redact_url(candidate.target),
            parameter=candidate.parameter,
            method=candidate.method.upper(),
            technique=candidate.technique,
            strategy=_STRATEGY,
            context=context.value if context else None,
            outcome=outcome,
            planned_repetitions=_REPETITIONS,
            completed_repetitions=self._completed_repetitions(samples),
            request_count=request_count,
            baseline_matches_true=baseline_matches_true,
            false_differs=false_differs,
            samples=tuple(samples),
            reason=reason,
            additional_verification_requirements=candidate.verification_required,
        )

    def _sample(
        self,
        group: str,
        repetition: int,
        request: TestRequest,
        response: Optional[TestResponse],
        original_value: str,
        context: SQLiValueContext,
        error_category: Optional[str] = None,
    ) -> SQLiVerificationSample:
        body = response.body if response is not None and isinstance(response.body, str) else ""
        value = next(iter(request.params.values()), "")
        normalized, reflection_neutralized = (
            self._normalize(body, str(value), original_value) if body else ("", False)
        )
        return SQLiVerificationSample(
            group=group,
            repetition=repetition,
            request_fingerprint=request.fingerprint,
            request_url=redact_url(request.build_url()),
            status_code=response.status_code if response is not None else None,
            response_sha256=hashlib.sha256(normalized.encode("utf-8")).hexdigest() if response is not None else None,
            response_length=len(body),
            completed_exchange=response.completed_exchange if response is not None else False,
            truncated=response.truncated if response is not None else False,
            body_is_decoded=response.body_is_decoded if response is not None else False,
            empty=not body.strip(),
            reflection_neutralized=reflection_neutralized,
            control_reflection_detected=self._contains_control_reflection(body, context, group),
            error_category=error_category,
        )

    async def verify(
        self,
        candidate: DetectionCandidate,
        original_value: object,
    ) -> SQLiVerificationReport:
        """Return a deterministic report without promoting or mutating candidate."""
        if not isinstance(candidate, DetectionCandidate):
            raise TypeError("candidate must be a DetectionCandidate")

        context = classify_original_value(original_value)
        if not is_sqli_finding_type(candidate.finding_type):
            return self._report(candidate, context=None, outcome=SQLiVerificationOutcome.NOT_TESTED,
                                reason="candidate is not SQL injection")
        if candidate.method.upper() != "GET" or not is_supported_parameter_name(candidate.parameter):
            return self._report(candidate, context=None, outcome=SQLiVerificationOutcome.NOT_TESTED,
                                reason="only GET query parameters with conservative names are supported")
        if context is None:
            return self._report(candidate, context=None, outcome=SQLiVerificationOutcome.NOT_TESTED,
                                reason="original value is outside the supported literal grammars")
        if not self._is_supported_target(candidate.target):
            return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.NOT_TESTED,
                                reason="target must be an HTTP endpoint without query, fragment, or userinfo")
        if self.request_engine is None or not callable(getattr(self.request_engine, "send_request", None)):
            return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.ERROR,
                                reason="request engine unavailable")

        values = {
            "baseline": str(original_value),
            "true": self._request_value(str(original_value), context, "true"),
            "false": self._request_value(str(original_value), context, "false"),
        }
        try:
            first_url = TestRequest(candidate.target, params={candidate.parameter: values["baseline"]}).build_url()
        except Exception:
            return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.NOT_TESTED,
                                reason="candidate request could not be constructed")
        if not self._is_authorized(first_url, "GET"):
            return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.NOT_TESTED,
                                reason="scope rejected the target before verification")

        try:
            available = self.budget_manager.limit(self.scan_id, first_url) - self.budget_manager.used(self.scan_id, first_url)
        except (InvalidBudgetOriginError, ValueError):
            return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.NOT_TESTED,
                                reason="target has no valid budget origin")
        if available < _REQUIRED_REQUESTS:
            return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.NOT_TESTED,
                                reason=f"verification requires {_REQUIRED_REQUESTS} available request reservations")

        samples: List[SQLiVerificationSample] = []
        observations: Dict[str, List[Tuple[TestResponse, str]]] = {
            "baseline": [], "true": [], "false": [],
        }
        request_count = 0
        rotations = (
            ("baseline", "true", "false"),
            ("true", "false", "baseline"),
            ("false", "baseline", "true"),
        )

        for repetition, order in enumerate(rotations):
            for group in order:
                value = values[group]
                payload = None if group == "baseline" else Payload(
                    value=value,
                    payload_type=PayloadType.BOOLEAN_BASED,
                    description=f"Read-only SQLi {group.upper()} control",
                )
                request = TestRequest(
                    url=candidate.target,
                    method="GET",
                    params={candidate.parameter: value},
                    follow_redirects=False,
                    payload=payload,
                )
                outcome = await self.execute_request(request)
                if (
                    outcome.status == AttemptStatus.SCOPE_REJECTED
                    and outcome.response is not None
                    and outcome.response.completed_exchange
                ):
                    request_count += 1
                elif outcome.status not in {AttemptStatus.SCOPE_REJECTED, AttemptStatus.BUDGET_EXHAUSTED}:
                    request_count += 1
                response = outcome.response
                sample = self._sample(
                    group, repetition, request, response, str(original_value),
                    context, outcome.error_category,
                )
                samples.append(sample)
                if outcome.ok and response is not None:
                    normalized, _ = self._normalize(
                        response.body, value, str(original_value)
                    )
                    observations[group].append((response, normalized))

                if outcome.status == AttemptStatus.BUDGET_EXHAUSTED:
                    status = (SQLiVerificationOutcome.NOT_TESTED if request_count == 0
                              else SQLiVerificationOutcome.INCONCLUSIVE)
                    reason = ("request budget was unavailable before verification began" if request_count == 0
                              else "request budget was exhausted during the verification sequence")
                    return self._report(candidate, context=context, outcome=status, reason=reason,
                                        request_count=request_count, samples=samples)
                if outcome.status == AttemptStatus.SCOPE_REJECTED:
                    status = (SQLiVerificationOutcome.NOT_TESTED if request_count == 0
                              else SQLiVerificationOutcome.INCONCLUSIVE)
                    reason = ("scope rejected the request before verification began" if request_count == 0
                              else "scope rejected a request or redirect during verification")
                    return self._report(candidate, context=context, outcome=status, reason=reason,
                                        request_count=request_count, samples=samples)
                if outcome.status == AttemptStatus.WAF_BLOCKED:
                    return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.INCONCLUSIVE,
                                        reason="a likely WAF interference prevented usable comparison",
                                        request_count=request_count, samples=samples)
                if outcome.status in {AttemptStatus.TIMEOUT, AttemptStatus.INCONCLUSIVE}:
                    return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.INCONCLUSIVE,
                                        reason="a required HTTP response was incomplete or timed out",
                                        request_count=request_count, samples=samples)
                if outcome.status == AttemptStatus.TRANSPORT_ERROR:
                    return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.ERROR,
                                        reason="request transport failed during verification",
                                        request_count=request_count, samples=samples)

        all_samples = [sample for group in ("baseline", "true", "false") for sample in observations[group]]
        if len(all_samples) != _REQUIRED_REQUESTS:
            return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.INCONCLUSIVE,
                                reason="verification did not produce all required response samples",
                                request_count=request_count, samples=samples)
        if any(not response.body.strip() for response, _ in all_samples):
            return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.INCONCLUSIVE,
                                reason="at least one required response body was empty",
                                request_count=request_count, samples=samples)
        if any(sample.control_reflection_detected for sample in samples):
            return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.INCONCLUSIVE,
                                reason="a Boolean control expression was reflected in a response",
                                request_count=request_count, samples=samples)
        if any(not response_is_analyzable(response) for response, _ in all_samples):
            return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.INCONCLUSIVE,
                                reason="at least one required response was incomplete, truncated, or undecoded",
                                request_count=request_count, samples=samples)
        statuses = [response.status_code for response, _ in all_samples]
        if len(set(statuses)) != 1 or any(status is None or not 200 <= status < 300 for status in statuses):
            return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.INCONCLUSIVE,
                                reason="response statuses were not uniformly successful and comparable",
                                request_count=request_count, samples=samples)

        normalized_groups = {
            group: [normalized for _, normalized in observations[group]]
            for group in ("baseline", "true", "false")
        }
        if any(len(set(group_values)) != 1 for group_values in normalized_groups.values()):
            return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.INCONCLUSIVE,
                                reason="repeated response content was unstable",
                                request_count=request_count, samples=samples)

        baseline_matches_true = normalized_groups["baseline"][0] == normalized_groups["true"][0]
        false_differs = normalized_groups["false"][0] != normalized_groups["true"][0]
        if baseline_matches_true and false_differs:
            return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.VERIFIED,
                                reason="three stable TRUE controls matched baseline and three FALSE controls differed",
                                request_count=request_count, samples=samples,
                                baseline_matches_true=True, false_differs=True)
        return self._report(candidate, context=context, outcome=SQLiVerificationOutcome.NOT_CONFIRMED,
                            reason="the complete stable Boolean comparison did not establish the required differential",
                            request_count=request_count, samples=samples,
                            baseline_matches_true=baseline_matches_true, false_differs=false_differs)

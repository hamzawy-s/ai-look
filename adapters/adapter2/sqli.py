"""Advanced, non-destructive SQL injection detection adapter."""
from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .framework import (
    AdapterScanResult,
    BaseVulnerabilityAdapter,
    Evidence,
    Payload,
    PayloadType,
    TestRequest,
    TestResponse,
    aggregate_coverage,
    response_is_analyzable,
)
from .models import TestOutcome
from .signatures import SQL_ERROR_SIGNATURES, Signature, SignatureMatcher


class DBMSType(Enum):
    MYSQL = "MySQL"
    MARIADB = "MariaDB"
    POSTGRESQL = "PostgreSQL"
    SQLSERVER = "Microsoft SQL Server"
    ORACLE = "Oracle"
    SQLITE = "SQLite"
    UNKNOWN = "Unknown"


class InjectionTechnique(Enum):
    ERROR_BASED = "ERROR_BASED"
    TIME_BASED = "TIME_BASED"
    BOOLEAN_BASED = "BOOLEAN_BASED"
    UNION_BASED = "UNION_BASED"


@dataclass
class SQLiDetectionResult:
    technique: InjectionTechnique
    dbms_type: DBMSType
    confidence: float
    payload_used: str
    evidence_list: List[Evidence]
    time_delta_ms: Optional[float] = None
    baseline_response: Optional[str] = None
    injected_response: Optional[str] = None

    @property
    def is_vulnerable(self) -> bool:
        return self.confidence >= 0.5


class SQLiDetector(BaseVulnerabilityAdapter):
    """Detect SQL injection without issuing destructive queries."""

    def __init__(
        self,
        request_engine,
        scope_engine,
        max_requests_per_target: int = 200,
        max_concurrent_requests: int = 3,
        time_based_threshold_ms: float = 4000.0,
        enable_time_based: bool = True,
        enable_union_based: bool = True,
        *,
        budget_manager=None,
        scan_id=None,
        waf_classifier=None,
    ):
        super().__init__(
            request_engine,
            scope_engine,
            max_requests_per_target,
            max_concurrent_requests,
            budget_manager=budget_manager,
            scan_id=scan_id,
            waf_classifier=waf_classifier,
        )
        self.time_based_threshold = time_based_threshold_ms
        self.enable_time_based = enable_time_based
        self.enable_union_based = enable_union_based
        self.signature_matcher = SignatureMatcher(SQL_ERROR_SIGNATURES)
        self.dbms_patterns = {
            DBMSType.MYSQL: [
                Signature("mysql", "MySQL error"),
                Signature("mariadb", "MariaDB"),
                Signature(r"sql syntax.*mysql", "MySQL syntax error", True),
            ],
            DBMSType.POSTGRESQL: [
                Signature("postgresql", "PostgreSQL error"),
                Signature("pg_query", "PostgreSQL query error"),
            ],
            DBMSType.SQLSERVER: [
                Signature("sql server", "SQL Server error"),
                Signature("unclosed quotation", "SQL Server quote error"),
                Signature(r"microsoft.*odbc", "ODBC error", True),
            ],
            DBMSType.ORACLE: [
                Signature(r"ora-[0-9]{5}", "Oracle error", True),
                Signature("oracle", "Oracle"),
            ],
            DBMSType.SQLITE: [
                Signature("sqlite", "SQLite error"),
                Signature(r"syntax error.*sqlite", "SQLite syntax", True),
            ],
        }

    @staticmethod
    def _request(url, parameter, value, payload=None, timeout=10.0):
        return TestRequest(
            url=url,
            method="GET",
            params={parameter: value},
            timeout_seconds=timeout,
            payload=payload,
        )

    async def detect_error_based(
        self, url, parameter, original_value, baseline_response
    ) -> Optional[SQLiDetectionResult]:
        payloads = [
            (f"{original_value}'", "Single quote"),
            (f'{original_value}"', "Double quote"),
            (f"{original_value}`", "Backtick"),
            (f"{original_value}' OR '1'='1", "OR true"),
            (f"{original_value} AND 1=1", "AND true"),
            (f"{original_value} AND 1=2", "AND false"),
        ]
        best = None
        for value, description in payloads:
            request = self._request(
                url, parameter, value,
                Payload(value, PayloadType.ERROR_BASED, description=description),
            )
            attempt = await self.execute_request(request)
            if not attempt.ok:
                self._capture_attempt(attempt)
                continue
            response = attempt.response
            if not response_is_analyzable(response):
                continue
            matches = self.signature_matcher.match(response.body)
            if not matches or self.signature_matcher.match(baseline_response.body):
                continue
            if value.lower() in response.body.lower():
                continue
            evidence = Evidence.from_request_response(
                request, response, matches[0].description
            )
            result = SQLiDetectionResult(
                InjectionTechnique.ERROR_BASED,
                self._identify_dbms(response.body),
                self._calculate_error_based_confidence(
                    matches, baseline_response, response
                ),
                value,
                [evidence],
                baseline_response=baseline_response.body[:500],
                injected_response=response.body[:500],
            )
            if best is None or result.confidence > best.confidence:
                best = result
        return best

    async def detect_time_based(
        self, url, parameter, original_value, baseline_elapsed_ms,
        dbms_type=DBMSType.UNKNOWN,
    ) -> Optional[SQLiDetectionResult]:
        if not self.enable_time_based:
            return None
        technique = {
            DBMSType.MYSQL: (f"{original_value} AND SLEEP(5)", "MySQL SLEEP"),
            DBMSType.POSTGRESQL: (f"{original_value}; SELECT pg_sleep(5)--", "PostgreSQL pg_sleep"),
            DBMSType.SQLSERVER: (f"{original_value}; WAITFOR DELAY '0:0:5'--", "SQL Server WAITFOR"),
            DBMSType.ORACLE: (f"{original_value} AND DBMS_LOCK.SLEEP(5)=0", "Oracle DBMS_LOCK.SLEEP"),
        }.get(dbms_type)
        if technique is None:
            self._scan_problem_outcome = TestOutcome.INCONCLUSIVE
            self._scan_problem_reason = "time-based SQLi skipped because no supported DBMS was identified"
            return None
        value, description = technique
        controls, delays, requests = [], [], []
        for _ in range(3):
            control_request = self._request(url, parameter, original_value)
            control = await self.execute_request(control_request)
            delay_request = self._request(
                url, parameter, value,
                Payload(value, PayloadType.TIME_BASED, timeout_seconds=7.0,
                        description=description), timeout=7.0,
            )
            delay = await self.execute_request(delay_request)
            if not control.ok or not delay.ok:
                self._capture_attempt(control if not control.ok else delay)
                return None
            if not response_is_analyzable(control.response) or not response_is_analyzable(delay.response):
                self._scan_problem_outcome = TestOutcome.INCONCLUSIVE
                self._scan_problem_reason = "paired timing response was incomplete or undecodable"
                return None
            controls.append(control.response)
            delays.append(delay.response)
            requests.append(delay_request)
        control_times = [item.elapsed_ms for item in controls]
        delay_times = [item.elapsed_ms for item in delays]
        control_median = sorted(control_times)[1]
        delay_median = sorted(delay_times)[1]
        if max(control_times) - min(control_times) > max(1000.0, control_median * 0.5):
            self._scan_problem_outcome = TestOutcome.INCONCLUSIVE
            self._scan_problem_reason = "timing controls were unstable"
            return None
        delta = delay_median - control_median
        if delta < self.time_based_threshold or any(
            measured - max(control_times) < self.time_based_threshold * 0.75
            for measured in delay_times
        ):
            return None
        evidence = [Evidence.from_request_response(
            request, response,
            f"{description}; paired delay {response.elapsed_ms:.0f}ms versus control median {control_median:.0f}ms",
        ) for request, response in zip(requests, delays)]
        confidence = min(0.95, 0.55 + delta / (self.time_based_threshold * 10))
        return SQLiDetectionResult(
            InjectionTechnique.TIME_BASED, dbms_type, confidence, value, evidence,
            time_delta_ms=delta,
        )

    async def detect_boolean_based(
        self, url, parameter, original_value, baseline_response
    ) -> Optional[SQLiDetectionResult]:
        true_value = f"{original_value}' OR '1'='1"
        false_value = f"{original_value}' OR '1'='2"
        true_request = self._request(
            url, parameter, true_value,
            Payload(true_value, PayloadType.BOOLEAN_BASED,
                    description="Boolean true condition"),
        )
        false_request = self._request(
            url, parameter, false_value,
            Payload(false_value, PayloadType.BOOLEAN_BASED,
                    description="Boolean false condition"),
        )
        baseline_samples = [baseline_response]
        true_samples, false_samples = [], []
        for _ in range(2):
            attempt = await self.execute_request(self._request(url, parameter, original_value))
            if not attempt.ok:
                self._capture_attempt(attempt)
                return None
            baseline_samples.append(attempt.response)
        for _ in range(3):
            true_attempt = await self.execute_request(true_request)
            false_attempt = await self.execute_request(false_request)
            if not true_attempt.ok or not false_attempt.ok:
                self._capture_attempt(true_attempt if not true_attempt.ok else false_attempt)
                return None
            true_samples.append(true_attempt.response)
            false_samples.append(false_attempt.response)
        if not all(response_is_analyzable(item) for item in baseline_samples + true_samples + false_samples):
            return None
        if any(true_value in item.body or false_value in item.body for item in true_samples + false_samples):
            return None
        normalize = lambda body: re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b|\b\d{10,}\b", "<dynamic>", body, flags=re.I)
        normalized = [normalize(item.body) for item in baseline_samples + true_samples + false_samples]
        baseline_bodies = normalized[:3]
        true_bodies = normalized[3:6]
        false_bodies = normalized[6:]
        if len(set(baseline_bodies)) != 1 or len(set(true_bodies)) != 1 or len(set(false_bodies)) != 1:
            return None
        baseline_response = baseline_samples[0]
        true_response, false_response = true_samples[0], false_samples[0]
        if true_bodies[0] == false_bodies[0]:
            return None
        confidence = self._calculate_boolean_based_confidence(
            baseline_response, true_response, false_response
        )
        if confidence < 0.5:
            return None
        return SQLiDetectionResult(
            InjectionTechnique.BOOLEAN_BASED,
            DBMSType.UNKNOWN,
            confidence,
            true_value,
            [
                *[Evidence.from_request_response(true_request, item, "Repeated stable TRUE-condition response") for item in true_samples],
                *[Evidence.from_request_response(false_request, item, "Repeated stable FALSE-condition response") for item in false_samples],
            ],
            baseline_response=baseline_response.body[:500],
            injected_response=true_response.body[:500],
        )

    async def detect_union_based(
        self, url, parameter, original_value
    ) -> Optional[SQLiDetectionResult]:
        if not self.enable_union_based:
            return None
        for count in range(1, 6):
            canary = "AILOOK" + secrets.token_hex(8)
            value = "' UNION SELECT " + ",".join(["NULL"] * (count - 1) + [f"'{canary}'"]) + "--"
            request = self._request(
                url, parameter, value,
                Payload(value, PayloadType.ERROR_BASED,
                        description=f"Union with {count} columns"),
            )
            attempt = await self.execute_request(request)
            if not attempt.ok:
                self._capture_attempt(attempt)
                continue
            response = attempt.response
            if not response_is_analyzable(response):
                continue
            if value.lower() in response.body.lower() or "union select" in response.body.lower():
                continue
            if canary in response.body:
                return SQLiDetectionResult(
                    InjectionTechnique.UNION_BASED,
                    DBMSType.UNKNOWN,
                    0.7 + (0.05 * (5 - count)),
                    value,
                    [Evidence.from_request_response(
                        request, response,
                        f"Union-based with {count} columns",
                    )],
                )
        return None

    def _identify_dbms(self, response_body: str) -> DBMSType:
        for dbms, patterns in self.dbms_patterns.items():
            if any(pattern.matches(response_body) for pattern in patterns):
                return dbms
        return DBMSType.UNKNOWN

    def _calculate_error_based_confidence(self, matches, baseline, injected):
        confidence = min(len(matches) * 0.25, 0.5)
        if injected.is_error and not baseline.is_error:
            confidence += 0.2
        confidence += 0.1 * sum(
            match.severity_hint == "HIGH" for match in matches
        )
        return min(confidence, 1.0)

    def _calculate_time_based_confidence(self, elapsed_ms, baseline_elapsed_ms):
        if elapsed_ms < self.time_based_threshold:
            return 0.0
        if baseline_elapsed_ms >= self.time_based_threshold:
            return 0.0
        threshold_delta = self.time_based_threshold - baseline_elapsed_ms
        if threshold_delta <= 0:
            return 1.0
        return max(
            min((elapsed_ms - baseline_elapsed_ms) / threshold_delta, 1.0) * 0.9,
            0.5,
        )

    def _calculate_boolean_based_confidence(self, baseline, true_response, false_response):
        baseline_hash = hashlib.md5(baseline.body.encode()).hexdigest()
        true_hash = hashlib.md5(true_response.body.encode()).hexdigest()
        false_hash = hashlib.md5(false_response.body.encode()).hexdigest()
        if true_hash == false_hash:
            return 0.0
        confidence = 0.5
        if true_hash != baseline_hash:
            confidence += 0.2
        if false_hash == baseline_hash:
            confidence += 0.2
        return min(confidence, 1.0)

    async def _scan_parameter_legacy(self, url, parameter, original_value):
        baseline_request = self._request(url, parameter, original_value)
        baseline_attempt = await self.execute_request(baseline_request)
        if not baseline_attempt.ok:
            self._capture_attempt(baseline_attempt)
            return None
        baseline = baseline_attempt.response
        if not response_is_analyzable(baseline):
            self._scan_problem_outcome = TestOutcome.INCONCLUSIVE
            self._scan_problem_reason = "baseline response was incomplete or undecodable"
            return None
        techniques: List[Tuple[str, object]] = [
            ("error_based", self.detect_error_based),
            ("boolean_based", self.detect_boolean_based),
        ]
        if self.enable_time_based:
            techniques.insert(1, ("time_based", self.detect_time_based))
        if self.enable_union_based:
            techniques.append(("union_based", self.detect_union_based))
        for name, technique in techniques:
            try:
                if name == "time_based":
                    dbms = self._identify_dbms(baseline.body)
                    result = await technique(
                        url, parameter, original_value, baseline.elapsed_ms, dbms
                    )
                elif name == "union_based":
                    result = await technique(url, parameter, original_value)
                else:
                    result = await technique(
                        url, parameter, original_value, baseline
                    )
            except Exception:
                continue
            if result and result.is_vulnerable:
                return self._create_sqli_candidate(url, parameter, result, name)
        return None

    async def scan_parameter(self, url, parameter, original_value=None):
        if not self._is_authorized(url, "GET"):
            return AdapterScanResult([], [], TestOutcome.SKIPPED,
                                     "scope rejected before test execution", 0)
        if self.request_engine is None or not callable(getattr(self.request_engine, "send_request", None)):
            return AdapterScanResult([], [], TestOutcome.ERROR,
                                     "request engine unavailable", 0)
        self._scan_problem_outcome = None
        self._scan_problem_reason = None
        candidate = await self._scan_parameter_legacy(
            url, parameter, "test" if original_value is None else original_value
        )
        return AdapterScanResult(
            findings=[], candidates=[candidate] if candidate else [],
            coverage_outcome=(TestOutcome.INCONCLUSIVE if candidate else self._scan_problem_outcome or TestOutcome.ABSENT),
            reason=(candidate.reason if candidate else self._scan_problem_reason or "completed analyzable probes without a candidate"),
            evidence_count=len(candidate.evidence) if candidate else 0,
        )

    def _create_sqli_candidate(self, url, parameter, result, technique_name):
        if not result.evidence_list:
            return None
        return self.make_candidate(
            finding_type="SQL_INJECTION", target=url, parameter=parameter,
            method="GET", technique=technique_name, confidence=result.confidence,
            evidence=result.evidence_list,
            reason="probe behavior is suggestive but does not establish database evaluation",
        )

    async def scan(self, target_url, parameters=None) -> AdapterScanResult:
        if parameters is None:
            parameters = list(parse_qs(urlparse(target_url).query).keys())
        items = list(parameters.items()) if isinstance(parameters, dict) else [(p, "test") for p in parameters]
        candidates, outcomes = [], []
        for parameter, value in items:
            result = await self.scan_parameter(target_url, parameter, value)
            candidates.extend(result.candidates)
            outcomes.append(result.coverage_outcome)
        return AdapterScanResult(
            findings=[], candidates=candidates,
            coverage_outcome=(TestOutcome.INCONCLUSIVE if candidates else aggregate_coverage(outcomes)),
            reason="SQLi probes completed" if items else "no query parameters to test",
            evidence_count=sum(len(candidate.evidence) for candidate in candidates),
        )

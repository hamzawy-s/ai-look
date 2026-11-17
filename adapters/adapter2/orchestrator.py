"""Bridge adapter results to coverage, the existing Core pipeline, and reports."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Tuple

from core_engine import Finding, FindingStatus, ObservationStatus, Severity

from .coverage import CoverageCollector
from .framework import AdapterScanResult, DetectionCandidate, aggregate_coverage
from .models import AdapterContext, CoverageRecord, TestOutcome
from .redaction import redact_url, sanitize_snippet
from .sqli import SQLiDetector
from .sqli_verification import (
    SQLiVerificationOutcome,
    SQLiVerificationReport,
    SQLiVerifier,
    candidate_fingerprint,
    classify_original_value,
    is_sqli_finding_type,
    is_supported_parameter_name,
)
from .xss import XSSDetector
from .xss_verification import (
    XSSVerificationOutcome,
    XSSVerificationReport,
    XSSVerifier,
    is_xss_finding_type,
    is_supported_xss_parameter_name,
)


@dataclass
class AssessmentResult:
    project_id: str
    scan_id: str
    target: str
    findings: List[Finding] = field(default_factory=list)
    candidates: List[DetectionCandidate] = field(default_factory=list)
    coverage_records: List[CoverageRecord] = field(default_factory=list)
    verification_reports: List[SQLiVerificationReport] = field(default_factory=list)
    coverage_outcome: TestOutcome = TestOutcome.SKIPPED
    reason: str = ""
    xss_verification_reports: List[XSSVerificationReport] = field(default_factory=list)

    @property
    def evidence_count(self) -> int:
        """Count reportable candidate and confirmed-finding evidence items."""
        candidate_evidence = sum(len(candidate.evidence) for candidate in self.candidates)
        finding_evidence = sum(len(finding.evidence) for finding in self.findings)
        return candidate_evidence + finding_evidence


class AssessmentOrchestrator:
    """Accumulate adapter observations and send only Core Findings to Core."""

    def __init__(self, context: AdapterContext, findings_pipeline, reporter=None):
        if not isinstance(context.coverage, CoverageCollector):
            raise TypeError("AssessmentOrchestrator requires the shared CoverageCollector")
        if context.coverage.scan_id != context.scan_id:
            raise ValueError("CoverageCollector scan_id does not match AdapterContext")
        if not context.scan_id or not context.project_id or not context.target_url:
            raise ValueError("assessment context requires project, scan, and target identity")
        self.context = context
        self.pipeline = findings_pipeline
        self.reporter = reporter
        self._raw_findings: Dict[str, Finding] = {}
        self._candidates: Dict[Tuple[str, str, str, str, str], DetectionCandidate] = {}
        self._verification_reports: Dict[str, SQLiVerificationReport] = {}
        self._xss_verification_reports: Dict[str, XSSVerificationReport] = {}
        self._outcomes: List[TestOutcome] = []
        self._reasons: List[str] = []
        self._finalized = False

    def add_result(
        self,
        adapter_name: str,
        result: AdapterScanResult,
        *,
        target: Optional[str] = None,
        finding_type: Optional[str] = None,
        parameter: str = "",
        method: str = "GET",
        test_family: Optional[str] = None,
        input_id: Optional[str] = None,
        parameter_location: str = "QUERY",
    ) -> None:
        if self._finalized:
            raise RuntimeError("assessment has already been finalized")
        if not adapter_name:
            raise ValueError("adapter_name must be non-empty")
        if not isinstance(result, AdapterScanResult):
            raise TypeError("result must be an AdapterScanResult")
        if not isinstance(result.coverage_outcome, TestOutcome):
            raise TypeError("coverage_outcome must be TestOutcome")
        destination = target or self.context.target_url
        family = test_family or adapter_name.upper()
        result_outcome = result.coverage_outcome
        if result.findings and result_outcome == TestOutcome.ABSENT:
            result_outcome = TestOutcome.PRESENT
        if result.candidates and result_outcome == TestOutcome.ABSENT:
            result_outcome = TestOutcome.INCONCLUSIVE
        self._outcomes.append(result_outcome)
        if result.reason:
            self._reasons.append(f"{adapter_name}: {result.reason}")

        identities = set()
        for finding in result.findings:
            if not isinstance(finding, Finding):
                raise TypeError("AdapterScanResult.findings may contain only Core Finding values")
            if finding.observation_status.value != "PRESENT":
                raise ValueError("adapters may submit only confirmed PRESENT Core Findings")
            if is_sqli_finding_type(finding.type):
                raise ValueError(
                    "SQLi Findings must be promoted by assess_sqli after a matching VERIFIED report"
                )
            if is_xss_finding_type(finding.type):
                raise ValueError(
                    "XSS Findings must be promoted by assess_xss after a matching VERIFIED report"
                )
            fingerprint = self.context.dedup_engine.generate_fingerprint(finding)
            finding.fingerprint = fingerprint
            self._raw_findings.setdefault(fingerprint, finding)
            identities.add((finding.type, finding.target, finding.parameter, finding.method or method))

        for candidate in result.candidates:
            if not isinstance(candidate, DetectionCandidate):
                raise TypeError("AdapterScanResult.candidates may contain only DetectionCandidate values")
            key = self._candidate_key(candidate)
            report = self._verification_reports.get(candidate_fingerprint(candidate))
            if report is not None and report.outcome == SQLiVerificationOutcome.VERIFIED:
                continue
            xss_report = self._xss_verification_reports.get(candidate_fingerprint(candidate))
            if xss_report is not None and xss_report.outcome == XSSVerificationOutcome.VERIFIED:
                continue
            candidate = self._store_candidate(candidate)
            identities.add((candidate.finding_type, candidate.target,
                            candidate.parameter, candidate.method))

        if not identities:
            identities.add((finding_type or adapter_name.upper(), destination, parameter, method))
        for type_name, item_target, item_parameter, item_method in identities:
            self.context.coverage.record(
                input_id=input_id or item_parameter or adapter_name,
                test_family=family,
                outcome=result_outcome,
                target=item_target,
                finding_type=type_name,
                parameter=item_parameter,
                method=item_method,
                parameter_location=parameter_location,
                evidence=[result.reason] if result.reason else [],
                reason=result.reason,
            )

    @staticmethod
    def _candidate_key(candidate: DetectionCandidate) -> Tuple[str, str, str, str, str]:
        return (
            candidate.finding_type.strip().upper(),
            candidate.target,
            candidate.parameter,
            candidate.method.upper(),
            candidate.technique.lower(),
        )

    def _store_candidate(self, candidate: DetectionCandidate) -> DetectionCandidate:
        """Deduplicate candidates without merging different identities."""
        key = self._candidate_key(candidate)
        existing = self._candidates.get(key)
        if existing is None:
            self._candidates[key] = candidate
            return candidate
        evidence_by_key = {
            (item.request_url, item.request_method, item.response_status,
             item.matched_signature, item.elapsed_ms): item
            for item in (*existing.evidence, *candidate.evidence)
        }
        merged = DetectionCandidate(
            candidate.finding_type,
            candidate.target,
            candidate.parameter,
            candidate.method,
            candidate.technique,
            max(existing.confidence, candidate.confidence),
            tuple(evidence_by_key.values()),
            candidate.reason,
            candidate.verification_required,
        )
        self._candidates[key] = merged
        return merged

    def _record_sqli_coverage(
        self,
        *,
        parameter: str,
        outcome: TestOutcome,
        reason: str,
        family: str,
    ) -> None:
        self.context.coverage.record(
            input_id=parameter or "SQLI",
            test_family=family,
            outcome=outcome,
            target=self.context.target_url,
            finding_type="SQL_INJECTION",
            parameter=parameter,
            method="GET",
            parameter_location="QUERY",
            evidence=[reason] if reason else [],
            reason=reason,
        )

    def _input_report(
        self,
        parameter: str,
        outcome: SQLiVerificationOutcome,
        reason: str,
    ) -> SQLiVerificationReport:
        fingerprint = self.context.dedup_engine.fingerprint_for(
            "GET", self.context.target_url, "SQL_INJECTION", parameter
        )
        return SQLiVerificationReport(
            candidate_fingerprint=None,
            finding_fingerprint=fingerprint,
            finding_type="SQL_INJECTION",
            target=redact_url(self.context.target_url),
            parameter=parameter,
            method="GET",
            technique="not_run",
            strategy="repeated_boolean_differential_v1",
            context=None,
            outcome=outcome,
            planned_repetitions=3,
            completed_repetitions=0,
            request_count=0,
            baseline_matches_true=None,
            false_differs=None,
            samples=(),
            reason=reason,
            additional_verification_requirements="a supported original value and authorized HTTP endpoint are required",
        )

    async def assess_sqli(
        self,
        detector: SQLiDetector,
        parameters: Mapping[str, str],
    ) -> List[SQLiVerificationReport]:
        """Run safe SQLi detection, verify its candidates, and gate promotion.

        Callers explicitly invoke this method because Phase 4 has no automatic
        scan runner. Detection uses only SQLiDetector.scan_parameter_safe,
        which sends a baseline and read-only AND controls; it never invokes the
        legacy quote-breakout, OR, time, or UNION probes. The detector must
        share this assessment's exact engine, scope, budget, and scan ID.
        """
        if self._finalized:
            raise RuntimeError("assessment has already been finalized")
        if not isinstance(detector, SQLiDetector):
            raise TypeError("detector must be an SQLiDetector")
        if not isinstance(parameters, Mapping):
            raise TypeError("parameters must map query names to original string values")
        if detector.request_engine is not self.context.request_engine:
            raise ValueError("SQLi detector must reuse the assessment RequestEngine")
        if detector.scope_engine is not self.context.scope_engine:
            raise ValueError("SQLi detector must reuse the assessment ScopeEngine")
        if self.context.budget_manager is None or detector.budget_manager is not self.context.budget_manager:
            raise ValueError("SQLi detector must reuse the assessment BudgetManager")
        if detector.scan_id != self.context.scan_id:
            raise ValueError("SQLi detector scan_id must match the assessment")
        if detector.enable_time_based or detector.enable_union_based:
            raise ValueError("Phase 5 orchestration requires time-based and UNION probes to be disabled")

        verifier = SQLiVerifier(
            detector.request_engine,
            detector.scope_engine,
            budget_manager=detector.budget_manager,
            scan_id=detector.scan_id,
            max_concurrent_requests=detector.max_concurrent_requests,
        )
        new_reports: List[SQLiVerificationReport] = []
        valid_parameters: Dict[str, str] = {}

        for parameter, original_value in parameters.items():
            if not is_supported_parameter_name(parameter):
                parameter_label = sanitize_snippet(parameter, 64)
                report = self._input_report(
                    parameter_label, SQLiVerificationOutcome.NOT_TESTED,
                    "query parameter name is outside the supported grammar; no request was sent",
                )
                self._verification_reports[f"input:{report.finding_fingerprint}:{parameter_label}"] = report
                new_reports.append(report)
                self._record_sqli_coverage(parameter=parameter_label, outcome=TestOutcome.SKIPPED,
                                           reason=report.reason, family="SQLI_VERIFICATION")
                self._outcomes.append(TestOutcome.SKIPPED)
                self._reasons.append(f"SQLI {parameter_label}: {report.reason}")
                continue
            value_context = classify_original_value(original_value)
            if value_context is None:
                report = self._input_report(
                    str(parameter), SQLiVerificationOutcome.NOT_TESTED,
                    "original value is outside the supported literal grammars; no request was sent",
                )
                self._verification_reports[f"input:{report.finding_fingerprint}:{parameter}"] = report
                new_reports.append(report)
                self._record_sqli_coverage(parameter=str(parameter), outcome=TestOutcome.SKIPPED,
                                           reason=report.reason, family="SQLI_VERIFICATION")
                self._outcomes.append(TestOutcome.SKIPPED)
                self._reasons.append(f"SQLI {parameter}: {report.reason}")
                continue
            valid_parameters[str(parameter)] = original_value

        if not SQLiVerifier._is_supported_target(self.context.target_url):
            for parameter in valid_parameters:
                report = self._input_report(
                    parameter, SQLiVerificationOutcome.NOT_TESTED,
                    "assessment target is not a supported query-free HTTP endpoint",
                )
                self._verification_reports[f"input:{report.finding_fingerprint}:{parameter}"] = report
                new_reports.append(report)
                self._record_sqli_coverage(parameter=parameter, outcome=TestOutcome.SKIPPED,
                                           reason=report.reason, family="SQLI_VERIFICATION")
                self._outcomes.append(TestOutcome.SKIPPED)
                self._reasons.append(f"SQLI {parameter}: {report.reason}")
            return new_reports

        for parameter, original_value in valid_parameters.items():
            try:
                result = await detector.scan_parameter_safe(
                    self.context.target_url, parameter, original_value
                )
            except Exception as exc:
                reason = f"SQLi detection failed: {type(exc).__name__}"
                report = self._input_report(parameter, SQLiVerificationOutcome.ERROR, reason)
                self._verification_reports[f"input:{report.finding_fingerprint}:{parameter}"] = report
                new_reports.append(report)
                self._record_sqli_coverage(parameter=parameter, outcome=TestOutcome.ERROR,
                                           reason=reason, family="SQLI_DETECTION")
                self._outcomes.append(TestOutcome.ERROR)
                self._reasons.append(f"SQLI {parameter}: {reason}")
                continue

            if result.findings:
                raise ValueError("SQLiDetector must return candidates, never confirmed Findings")
            if not result.candidates:
                self._record_sqli_coverage(
                    parameter=parameter,
                    outcome=result.coverage_outcome,
                    reason=result.reason,
                    family="SQLI_DETECTION",
                )
                self._outcomes.append(result.coverage_outcome)
                if result.reason:
                    self._reasons.append(f"SQLI {parameter}: {result.reason}")
                continue

            for candidate in result.candidates:
                if candidate.parameter != parameter or candidate.target != redact_url(self.context.target_url):
                    raise ValueError("SQLi candidate identity does not match the scanned input")
                if not is_sqli_finding_type(candidate.finding_type) or candidate.method.upper() != "GET":
                    raise ValueError("SQLiDetector returned an unsupported candidate identity")

                stored_candidate = self._store_candidate(candidate)
                candidate_id = candidate_fingerprint(stored_candidate)
                prior_report = self._verification_reports.get(candidate_id)
                if prior_report is not None:
                    report = prior_report
                else:
                    self._record_sqli_coverage(
                        parameter=parameter,
                        outcome=TestOutcome.INCONCLUSIVE,
                        reason="SQLi detection produced an unverified candidate",
                        family="SQLI_DETECTION",
                    )
                    report = await verifier.verify(stored_candidate, original_value)
                    self._verification_reports[candidate_id] = report
                new_reports.append(report)
                self._reasons.append(f"SQLI {parameter}: {report.reason}")

                if report.outcome == SQLiVerificationOutcome.VERIFIED:
                    key = self._candidate_key(stored_candidate)
                    current = self._candidates.get(key)
                    if current is None or candidate_fingerprint(current) != report.candidate_fingerprint:
                        raise RuntimeError("verified candidate identity changed before promotion")
                    del self._candidates[key]
                    finding = self._finding_from_verified_candidate(stored_candidate, report)
                    self._raw_findings.setdefault(finding.fingerprint, finding)
                    coverage_outcome = TestOutcome.PRESENT
                else:
                    coverage_outcome = {
                        SQLiVerificationOutcome.NOT_CONFIRMED: TestOutcome.ABSENT,
                        SQLiVerificationOutcome.INCONCLUSIVE: TestOutcome.INCONCLUSIVE,
                        SQLiVerificationOutcome.NOT_TESTED: TestOutcome.SKIPPED,
                        SQLiVerificationOutcome.ERROR: TestOutcome.ERROR,
                    }[report.outcome]
                self._record_sqli_coverage(
                    parameter=parameter,
                    outcome=coverage_outcome,
                    reason=report.reason,
                    family="SQLI_VERIFICATION",
                )
                self._outcomes.append(coverage_outcome)
        return new_reports

    def _record_xss_coverage(
        self,
        *,
        parameter: str,
        outcome: TestOutcome,
        reason: str,
        family: str,
    ) -> None:
        self.context.coverage.record(
            input_id=parameter or "XSS",
            test_family=family,
            outcome=outcome,
            target=self.context.target_url,
            finding_type="XSS",
            parameter=parameter,
            method="GET",
            parameter_location="QUERY",
            evidence=[reason] if reason else [],
            reason=reason,
        )

    def _xss_input_report(
        self,
        parameter: str,
        outcome: XSSVerificationOutcome,
        reason: str,
    ) -> XSSVerificationReport:
        finding_fingerprint = self.context.dedup_engine.fingerprint_for(
            "GET", self.context.target_url, "XSS", parameter,
        )
        return XSSVerificationReport(
            candidate_fingerprint=None,
            finding_fingerprint=finding_fingerprint,
            target=redact_url(self.context.target_url),
            parameter=parameter,
            outcome=outcome,
            reason=reason,
            cleanup_completed=True,
        )

    async def assess_xss(
        self,
        detector: XSSDetector,
        parameters: Mapping[str, str],
    ) -> List[XSSVerificationReport]:
        """Safely screen query parameters and verify only matching XSS candidates.

        Values in ``parameters`` are intentionally not sent or retained. The
        detector substitutes an inert, unique marker and the verifier sends
        one controlled local-only proof payload for supported HTML body text.
        """
        if self._finalized:
            raise RuntimeError("assessment has already been finalized")
        if not isinstance(detector, XSSDetector):
            raise TypeError("detector must be an XSSDetector")
        if not isinstance(parameters, Mapping):
            raise TypeError("parameters must map query parameter names to original values")
        if detector.request_engine is not self.context.request_engine:
            raise ValueError("XSS detector must reuse the assessment RequestEngine")
        if detector.scope_engine is not self.context.scope_engine:
            raise ValueError("XSS detector must reuse the assessment ScopeEngine")
        if self.context.budget_manager is None or detector.budget_manager is not self.context.budget_manager:
            raise ValueError("XSS detector must reuse the assessment BudgetManager")
        if detector.scan_id != self.context.scan_id:
            raise ValueError("XSS detector scan_id must match the assessment")

        new_reports: List[XSSVerificationReport] = []

        for parameter, _original_value in parameters.items():
            parameter_label = sanitize_snippet(parameter, 64) if isinstance(parameter, str) else "[INVALID]"
            if not is_supported_xss_parameter_name(parameter):
                reason = "query parameter name is outside the supported grammar; no request was sent"
                report = self._xss_input_report(
                    parameter_label,
                    XSSVerificationOutcome.NOT_TESTED,
                    reason,
                )
                self._xss_verification_reports[
                    f"input:{report.finding_fingerprint}:{parameter_label}"
                ] = report
                new_reports.append(report)
                self._record_xss_coverage(
                    parameter=parameter_label,
                    outcome=TestOutcome.SKIPPED,
                    reason=reason,
                    family="XSS_REFLECTION",
                )
                self._outcomes.append(TestOutcome.SKIPPED)
                self._reasons.append(f"XSS {parameter_label}: {reason}")
                continue

            if not detector._is_authorized(self.context.target_url, "GET"):
                reason = "assessment target was rejected by scope before XSS requests were sent"
                report = self._xss_input_report(
                    str(parameter), XSSVerificationOutcome.BLOCKED, reason,
                )
                self._xss_verification_reports[
                    f"input:{report.finding_fingerprint}:{parameter}"
                ] = report
                new_reports.append(report)
                self._record_xss_coverage(
                    parameter=str(parameter), outcome=TestOutcome.BLOCKED,
                    reason=reason, family="XSS_REFLECTION",
                )
                self._outcomes.append(TestOutcome.BLOCKED)
                self._reasons.append(f"XSS {parameter}: {reason}")
                continue

            try:
                result = await detector.scan_parameter_safe(
                    self.context.target_url, parameter,
                )
            except Exception as exc:
                reason = f"XSS reflection screen failed: {type(exc).__name__}"
                report = self._xss_input_report(
                    str(parameter), XSSVerificationOutcome.ERROR, reason,
                )
                self._xss_verification_reports[
                    f"input:{report.finding_fingerprint}:{parameter}"
                ] = report
                new_reports.append(report)
                self._record_xss_coverage(
                    parameter=str(parameter), outcome=TestOutcome.ERROR,
                    reason=reason, family="XSS_REFLECTION",
                )
                self._outcomes.append(TestOutcome.ERROR)
                self._reasons.append(f"XSS {parameter}: {reason}")
                continue

            if result.findings:
                raise ValueError("XSSDetector must return candidates, never confirmed Findings")
            if not result.candidates:
                outcome = {
                    TestOutcome.SKIPPED: XSSVerificationOutcome.NOT_TESTED,
                    TestOutcome.BLOCKED: XSSVerificationOutcome.BLOCKED,
                    TestOutcome.ERROR: XSSVerificationOutcome.ERROR,
                    TestOutcome.PRESENT: XSSVerificationOutcome.INCONCLUSIVE,
                    TestOutcome.ABSENT: XSSVerificationOutcome.INCONCLUSIVE,
                    TestOutcome.INCONCLUSIVE: XSSVerificationOutcome.INCONCLUSIVE,
                }[result.coverage_outcome]
                report = self._xss_input_report(str(parameter), outcome, result.reason)
                self._xss_verification_reports[
                    f"input:{report.finding_fingerprint}:{parameter}"
                ] = report
                self._record_xss_coverage(
                    parameter=str(parameter),
                    outcome=(TestOutcome.INCONCLUSIVE
                             if result.coverage_outcome == TestOutcome.ABSENT
                             else result.coverage_outcome),
                    reason=result.reason, family="XSS_REFLECTION",
                )
                self._outcomes.append(
                    TestOutcome.INCONCLUSIVE
                    if result.coverage_outcome == TestOutcome.ABSENT
                    else result.coverage_outcome
                )
                self._reasons.append(f"XSS {parameter}: {result.reason}")
                new_reports.append(report)
                continue

            for candidate in result.candidates:
                if not isinstance(candidate, DetectionCandidate):
                    raise TypeError("XSSDetector candidates must be DetectionCandidate values")
                if (
                    not is_xss_finding_type(candidate.finding_type)
                    or candidate.target != redact_url(self.context.target_url)
                    or candidate.parameter != parameter
                    or candidate.method.upper() != "GET"
                    or candidate.technique != "reflected-inert-marker-v1"
                ):
                    raise ValueError("XSS candidate identity does not match the scanned query input")

                candidate_id = candidate_fingerprint(candidate)
                prior_report = self._xss_verification_reports.get(candidate_id)
                if prior_report is not None and prior_report.outcome == XSSVerificationOutcome.VERIFIED:
                    new_reports.append(prior_report)
                    continue

                stored_candidate = self._store_candidate(candidate)
                candidate_id = candidate_fingerprint(stored_candidate)
                self._record_xss_coverage(
                    parameter=str(parameter), outcome=TestOutcome.INCONCLUSIVE,
                    reason="XSS detection produced an unverified inert-reflection candidate",
                    family="XSS_REFLECTION",
                )
                if prior_report is None:
                    verifier = XSSVerifier(
                        detector.request_engine,
                        detector.scope_engine,
                        budget_manager=detector.budget_manager,
                        scan_id=detector.scan_id,
                        max_concurrent_requests=detector.max_concurrent_requests,
                    )
                    report = await verifier.verify(stored_candidate)
                else:
                    report = prior_report
                if prior_report is None:
                    self._xss_verification_reports[candidate_id] = report
                new_reports.append(report)
                self._reasons.append(f"XSS {parameter}: {report.reason}")

                if report.outcome == XSSVerificationOutcome.VERIFIED:
                    if (
                        report.candidate_fingerprint != candidate_id
                        or report.target != redact_url(self.context.target_url)
                        or report.parameter != parameter
                    ):
                        raise RuntimeError("verified XSS report does not match the stored candidate")
                    key = self._candidate_key(stored_candidate)
                    current = self._candidates.get(key)
                    if current is None or candidate_fingerprint(current) != report.candidate_fingerprint:
                        raise RuntimeError("verified XSS candidate identity changed before promotion")
                    del self._candidates[key]
                    finding = self._finding_from_verified_xss_candidate(stored_candidate, report)
                    finding.fingerprint = self.context.dedup_engine.generate_fingerprint(finding)
                    self._raw_findings.setdefault(finding.fingerprint, finding)
                    coverage_outcome = TestOutcome.PRESENT
                else:
                    coverage_outcome = {
                        XSSVerificationOutcome.NOT_VERIFIED: TestOutcome.INCONCLUSIVE,
                        XSSVerificationOutcome.INCONCLUSIVE: TestOutcome.INCONCLUSIVE,
                        XSSVerificationOutcome.NOT_TESTED: TestOutcome.SKIPPED,
                        XSSVerificationOutcome.BLOCKED: TestOutcome.BLOCKED,
                        XSSVerificationOutcome.ERROR: TestOutcome.ERROR,
                    }[report.outcome]
                self._record_xss_coverage(
                    parameter=str(parameter), outcome=coverage_outcome,
                    reason=report.reason, family="XSS_VERIFICATION",
                )
                self._outcomes.append(coverage_outcome)
        return new_reports

    @staticmethod
    def _finding_from_verified_xss_candidate(
        candidate: DetectionCandidate,
        report: XSSVerificationReport,
    ) -> Finding:
        if (
            report.outcome != XSSVerificationOutcome.VERIFIED
            or report.candidate_fingerprint != candidate_fingerprint(candidate)
            or report.candidate_confidence != candidate.confidence
            or not report.proof_token_match
            or not report.payload_reflected_as_script
            or not report.request_telemetry_complete
            or not report.cleanup_completed
        ):
            raise ValueError("only a matching VERIFIED browser report may authorize XSS promotion")
        evidence = []
        for item in candidate.evidence[:6]:
            evidence.append(
                f"Detection: {sanitize_snippet(item.matched_signature, 120)}; "
                f"{item.request_method} {item.request_url}; HTTP {item.response_status}; "
                f"{sanitize_snippet(item.response_body_snippet, 240)}"
            )
        evidence.append(
            "Browser verification VERIFIED: controlled HTML body script executed and the exact "
            f"per-attempt token matched; token_sha256={report.proof_token_sha256}; "
            f"candidate={report.candidate_fingerprint}; requests={report.request_count}; "
            f"RequestEngine exchanges={report.request_engine_exchange_count}; "
            f"budget reservations={report.budget_reservation_count}."
        )
        return Finding(
            type="XSS",
            target=candidate.target,
            parameter=candidate.parameter,
            method=candidate.method.upper(),
            severity=Severity.HIGH,
            confidence=candidate.confidence,
            source="XSSVerifier",
            status=FindingStatus.OPEN,
            observation_status=ObservationStatus.PRESENT,
            evidence=evidence,
            remediation=("Apply context-appropriate output encoding and avoid inserting "
                         "untrusted input as executable HTML or JavaScript."),
            requires_human_review=True,
        )

    @staticmethod
    def _finding_from_verified_candidate(
        candidate: DetectionCandidate,
        report: SQLiVerificationReport,
    ) -> Finding:
        if report.outcome != SQLiVerificationOutcome.VERIFIED or report.candidate_fingerprint != candidate_fingerprint(candidate):
            raise ValueError("only the matching VERIFIED report may authorize SQLi promotion")
        evidence = []
        for item in candidate.evidence[:6]:
            evidence.append(
                f"Detection: {sanitize_snippet(item.matched_signature, 120)}; "
                f"{item.request_method} {item.request_url}; HTTP {item.response_status}; "
                f"{sanitize_snippet(item.response_body_snippet, 240)}"
            )
        evidence.append(
            "Boolean verification VERIFIED: three stable TRUE controls matched baseline; "
            "three stable FALSE controls differed after exact-input reflection neutralization. "
            f"Candidate={report.candidate_fingerprint}; requests={report.request_count}."
        )
        return Finding(
            type="SQL_INJECTION",
            target=candidate.target,
            parameter=candidate.parameter,
            method=candidate.method.upper(),
            severity=Severity.HIGH,
            confidence=candidate.confidence,
            source="SQLiVerifier",
            status=FindingStatus.OPEN,
            observation_status=ObservationStatus.PRESENT,
            evidence=evidence,
            remediation=("Use parameterized queries for all user-controlled values and avoid "
                         "constructing SQL statements through string concatenation."),
            requires_human_review=True,
        )

    async def finalize(self, report_path: Optional[str] = None) -> AssessmentResult:
        if self._finalized:
            raise RuntimeError("assessment has already been finalized")
        self._finalized = True
        await self.pipeline.db_manager.connect()
        findings = await self.pipeline.process(
            project_id=self.context.project_id,
            scan_id=self.context.scan_id,
            scan_date=self.context.scan_date,
            tested_fingerprints=self.context.coverage.tested_fingerprints(),
            raw_findings=list(self._raw_findings.values()),
        )
        outcome = aggregate_coverage(self._outcomes)
        assessment = AssessmentResult(
            project_id=self.context.project_id,
            scan_id=self.context.scan_id,
            target=self.context.target_url,
            findings=findings,
            candidates=list(self._candidates.values()),
            coverage_records=self.context.coverage.records(),
            verification_reports=list(self._verification_reports.values()),
            xss_verification_reports=list(self._xss_verification_reports.values()),
            coverage_outcome=outcome,
            reason="; ".join(dict.fromkeys(self._reasons)),
        )
        if report_path and self.reporter is not None:
            self.reporter.export_scan_result(assessment, report_path)
        return assessment

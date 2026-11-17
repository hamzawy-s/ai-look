"""Bridge adapter results to coverage, the existing Core pipeline, and reports."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from core_engine import Finding

from .coverage import CoverageCollector
from .framework import AdapterScanResult, DetectionCandidate, aggregate_coverage
from .models import AdapterContext, CoverageRecord, TestOutcome


@dataclass
class AssessmentResult:
    project_id: str
    scan_id: str
    target: str
    findings: List[Finding] = field(default_factory=list)
    candidates: List[DetectionCandidate] = field(default_factory=list)
    coverage_records: List[CoverageRecord] = field(default_factory=list)
    coverage_outcome: TestOutcome = TestOutcome.SKIPPED
    reason: str = ""

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
            fingerprint = self.context.dedup_engine.generate_fingerprint(finding)
            finding.fingerprint = fingerprint
            self._raw_findings.setdefault(fingerprint, finding)
            identities.add((finding.type, finding.target, finding.parameter, finding.method or method))

        for candidate in result.candidates:
            if not isinstance(candidate, DetectionCandidate):
                raise TypeError("AdapterScanResult.candidates may contain only DetectionCandidate values")
            key = (candidate.finding_type, candidate.target, candidate.parameter,
                   candidate.method, candidate.technique)
            existing = self._candidates.get(key)
            if existing:
                evidence_by_key = {
                    (item.request_url, item.request_method, item.response_status,
                     item.matched_signature, item.elapsed_ms): item
                    for item in (*existing.evidence, *candidate.evidence)
                }
                evidence = tuple(evidence_by_key.values())
                candidate = DetectionCandidate(
                    candidate.finding_type, candidate.target, candidate.parameter,
                    candidate.method, candidate.technique,
                    max(existing.confidence, candidate.confidence), evidence,
                    candidate.reason, candidate.verification_required,
                )
            self._candidates[key] = candidate
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
            coverage_outcome=outcome,
            reason="; ".join(dict.fromkeys(self._reasons)),
        )
        if report_path and self.reporter is not None:
            self.reporter.export_scan_result(assessment, report_path)
        return assessment

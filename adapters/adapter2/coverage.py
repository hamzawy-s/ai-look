from __future__ import annotations

from typing import Dict, List, Optional, Set

from core_engine import DeduplicationEngine

from .models import EXECUTED_OUTCOMES, CoverageRecord, TestOutcome


_PRECEDENCE = {
    TestOutcome.PRESENT: 6,
    TestOutcome.INCONCLUSIVE: 5,
    TestOutcome.BLOCKED: 4,
    TestOutcome.ERROR: 3,
    TestOutcome.SKIPPED: 2,
    TestOutcome.ABSENT: 1,
}


class CoverageCollector:
    """Adapter-owned coverage that feeds the Core tested_fingerprints contract.

    Uses the real Core fingerprint algorithm so coverage identities match
    finding identities without fabricating Findings for clean tests.
    """

    def __init__(self, dedup_engine: DeduplicationEngine, scan_id: str):
        self._dedup = dedup_engine
        self._scan_id = scan_id
        self._records: Dict[tuple, CoverageRecord] = {}

    @property
    def scan_id(self) -> str:
        return self._scan_id

    def record(
        self,
        *,
        input_id: str,
        test_family: str,
        outcome: TestOutcome,
        target: str,
        finding_type: str,
        parameter: str,
        method: Optional[str] = None,
        parameter_location: str = "QUERY",
        evidence: Optional[List[str]] = None,
        request_fingerprint: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> CoverageRecord:
        fingerprint = self._dedup.fingerprint_for(
            method, target, finding_type, parameter
        )
        key = (fingerprint, test_family)
        record = CoverageRecord(
            fingerprint=fingerprint,
            input_id=input_id,
            test_family=test_family,
            outcome=outcome,
            method=method,
            target=target,
            finding_type=finding_type,
            parameter=parameter,
            parameter_location=parameter_location,
            evidence=evidence or [],
            request_fingerprint=request_fingerprint,
            scan_id=self._scan_id,
            reason=reason,
        )
        existing = self._records.get(key)
        if existing is None or _PRECEDENCE[outcome] > _PRECEDENCE[existing.outcome]:
            self._records[key] = record
        return record

    def tested_fingerprints(self) -> Set[str]:
        return {
            record.fingerprint
            for record in self._records.values()
            if record.outcome in EXECUTED_OUTCOMES
        }

    def summary(self) -> Dict[str, int]:
        result = {outcome.value: 0 for outcome in TestOutcome}
        for record in self._records.values():
            result[record.outcome.value] += 1
        return result

    def records(self) -> List[CoverageRecord]:
        return list(self._records.values())

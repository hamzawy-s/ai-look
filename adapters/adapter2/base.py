from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import List, Optional

from core_engine import Finding

from .models import AdapterContext, TestOutcome


class BaseAdapter(ABC):
    """Minimum shared adapter contract for Phase 1.

    Coverage registration and finding creation are separate responsibilities.
    Scope validation fails closed when scope is missing, unauthorized, or raises.
    """

    def __init__(self, context: AdapterContext):
        self.context = context
        self.logger = logging.getLogger(f"Adapter2.{self.__class__.__name__}")
        self.findings: List[Finding] = []

    @abstractmethod
    async def execute(self) -> None:
        raise NotImplementedError

    def record_coverage(
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
    ) -> None:
        if self.context.coverage is None:
            self.logger.warning("No CoverageCollector; coverage not recorded.")
            return
        self.context.coverage.record(
            input_id=input_id,
            test_family=test_family,
            outcome=outcome,
            target=target,
            finding_type=finding_type,
            parameter=parameter,
            method=method,
            parameter_location=parameter_location,
            evidence=evidence,
            request_fingerprint=request_fingerprint,
            reason=reason,
        )

    def add_finding(self, finding: Finding) -> None:
        if finding.fingerprint is None and self.context.dedup_engine is not None:
            finding.fingerprint = self.context.dedup_engine.generate_fingerprint(finding)
        self.findings.append(finding)

    def is_authorized(self, url: str, method: str = "GET") -> bool:
        if self.context.scope_engine is None:
            self.logger.error("ScopeEngine unavailable; failing closed.")
            return False
        try:
            return bool(self.context.scope_engine.is_authorized(url, method))
        except Exception as exc:
            self.logger.error("Scope validation error (%s); failing closed.", exc)
            return False
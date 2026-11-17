"""Command injection adapter boundary; no target command is executed."""
from .framework import AdapterScanResult
from .models import TestOutcome


class CommandInjectionDetector:
    async def scan(self, request_context):
        return AdapterScanResult(
            findings=[], candidates=[], coverage_outcome=TestOutcome.SKIPPED,
            reason="CMDi verification is not implemented; no shell payload is sent",
            evidence_count=0,
        )

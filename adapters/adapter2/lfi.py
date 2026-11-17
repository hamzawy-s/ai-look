"""LFI adapter boundary; only a controlled temporary fixture is supported."""
from .framework import AdapterScanResult
from .models import TestOutcome


class LFIDetector:
    async def scan(self, request_context):
        return AdapterScanResult(
            findings=[], candidates=[], coverage_outcome=TestOutcome.SKIPPED,
            reason="LFI verification is not implemented; no operating-system paths are probed",
            evidence_count=0,
        )

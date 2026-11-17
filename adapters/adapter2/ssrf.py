"""SSRF adapter boundary.

No built-in target URL is requested. A bounded, explicitly allowlisted callback
service is required before a real verification workflow can be enabled.
"""
from .framework import AdapterScanResult
from .models import TestOutcome


class SSRFDetector:
    async def scan(self, request_context):
        return AdapterScanResult(
            findings=[], candidates=[], coverage_outcome=TestOutcome.SKIPPED,
            reason="SSRF verification is not implemented; configure an owned allowlisted callback first",
            evidence_count=0,
        )

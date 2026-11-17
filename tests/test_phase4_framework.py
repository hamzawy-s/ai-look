from dataclasses import FrozenInstanceError

import pytest

from adapters.adapter2.framework import (
    AdapterScanResult, DetectionCandidate, Evidence, TestRequest, TestResponse,
    response_is_analyzable, response_indicates_waf_block,
)
from adapters.adapter2.models import TestOutcome
from adapters.adapter2.request import RequestResult


def test_request_url_preserves_query_duplicates_blank_values_and_encoding():
    request = TestRequest(
        "https://example.test/path?x=1&x=&keep=a%20b#section",
        params=[("x", "2 3"), ("new", "")],
    )
    assert request.build_url() == (
        "https://example.test/path?x=1&x=&keep=a+b&x=2+3&new="
    )


@pytest.mark.parametrize(
    "response,expected",
    [
        (TestResponse(200, {}, "ok", 2), True),
        (TestResponse(200, {}, "partial", 2, completed_exchange=False), False),
        (TestResponse(200, {}, "partial", 2, truncated=True), False),
        (TestResponse(200, {}, "", 2, body_is_decoded=False), False),
    ],
)
def test_response_analyzability_contract(response, expected):
    assert response_is_analyzable(response) is expected


def test_waf_block_classification_requires_vendor_signal():
    assert not response_indicates_waf_block(TestResponse(403, {}, "Access denied", 4))
    assert response_indicates_waf_block(
        TestResponse(403, {"Server": "cloudflare"}, "blocked", 4)
    )


def test_candidate_is_separate_from_core_finding_and_result_contract():
    evidence = Evidence(
        "https://example.test/?id=1", "GET", {}, None, 200, {}, "marker",
        "marker", 4, truncated=False,
    )
    candidate = DetectionCandidate(
        "SQL_INJECTION", "https://example.test/", "id", "GET",
        "error-indicator", 0.7, (evidence,), "suggestive SQL error",
        "database-backed verification",
    )
    result = AdapterScanResult(
        findings=[], candidates=[candidate],
        coverage_outcome=TestOutcome.INCONCLUSIVE,
        reason="verification required", evidence_count=1,
    )
    assert result.findings == []
    assert result.candidates == [candidate]
    assert result.coverage_outcome == TestOutcome.INCONCLUSIVE
    with pytest.raises(FrozenInstanceError):
        candidate.confidence = 1.0


@pytest.mark.parametrize(
    "outcome",
    [TestOutcome.INCONCLUSIVE, TestOutcome.BLOCKED, TestOutcome.ERROR, TestOutcome.SKIPPED],
)
def test_coverage_collector_does_not_downgrade_non_absent_results(outcome):
    from adapters.adapter2.context import create_context

    context = create_context(
        project_id="coverage-project", scan_id="coverage-scan",
        scan_date="2026-11-17T00:00:00Z", target_url="https://example.test/",
    )
    arguments = dict(
        input_id="id", test_family="SQLI", target="https://example.test/",
        finding_type="SQL_INJECTION", parameter="id", method="GET",
    )
    context.coverage.record(outcome=outcome, reason="first observation", **arguments)
    context.coverage.record(outcome=TestOutcome.ABSENT, reason="later clean result", **arguments)

    records = context.coverage.records()
    assert len(records) == 1
    assert records[0].outcome == outcome


def test_report_keeps_candidate_separate_from_findings(tmp_path):
    import json
    from reporting.reporter import Reporter
    evidence = Evidence("https://example.test/", "GET", {}, None, 200, {}, "body", "marker", 1)
    candidate = DetectionCandidate("XSS", "https://example.test/", "q", "GET",
                                   "reflection", 0.4, (evidence,), "reflected", "browser")
    result = AdapterScanResult([], [candidate], TestOutcome.INCONCLUSIVE, "verification required", 1)
    output = tmp_path / "scan.json"
    Reporter().export_scan_result(result, str(output))
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["findings"] == []
    assert payload["candidates"][0]["finding_type"] == "XSS"
    assert payload["coverage_outcome"] == "INCONCLUSIVE"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "engine_result,expected_status,expected_coverage",
    [
        (RequestResult(False, "https://example.test/", error_category="timeout"), "TIMEOUT", TestOutcome.INCONCLUSIVE),
        (RequestResult(True, "https://example.test/", status_code=200, text="partial", truncated=True), "INCONCLUSIVE", TestOutcome.INCONCLUSIVE),
        (RequestResult(False, "https://example.test/", status_code=302, error_category="redirect_scope_rejected"), "SCOPE_REJECTED", TestOutcome.SKIPPED),
        (RequestResult(False, "https://example.test/", error_category="connection"), "TRANSPORT_ERROR", TestOutcome.ERROR),
    ],
)
async def test_framework_preserves_request_outcome_metadata(engine_result, expected_status, expected_coverage):
    from unittest.mock import AsyncMock
    from adapters.adapter2.framework import AttemptStatus, BaseVulnerabilityAdapter

    engine = type("Engine", (), {"send_request": AsyncMock(return_value=engine_result)})()
    scope = type("Scope", (), {"is_authorized": lambda self, url, method="GET": True})()
    adapter = BaseVulnerabilityAdapter(engine, scope)
    outcome = await adapter.execute_request(TestRequest("https://example.test/"))
    assert outcome.status == AttemptStatus[expected_status]
    assert outcome.coverage_outcome == expected_coverage


def test_evidence_redacts_url_headers_and_request_body():
    from adapters.adapter2.framework import Evidence, TestRequest
    evidence = Evidence.from_attempt(
        TestRequest(
            "https://example.test/?api_key=secret-value", headers={"Authorization": "Bearer abc"},
            body="password=hunter2",
        ),
        TestResponse(200, {"Set-Cookie": "sid=secret", "Content-Type": "text/plain"},
                    "token=private", 2),
        "test marker",
    )
    rendered = repr(evidence)
    for secret in ("secret-value", "Bearer abc", "hunter2", "sid=secret", "private"):
        assert secret not in rendered
    from adapters.adapter2.redaction import configure_secrets
    configure_secrets(["app-internal-secret"])
    try:
        assert "app-internal-secret" not in Evidence.from_attempt(
            TestRequest("https://example.test"),
            TestResponse(200, {}, "app-internal-secret", 1), "marker",
        ).response_body_snippet
    finally:
        configure_secrets([])


@pytest.mark.asyncio
async def test_unimplemented_active_probes_report_skipped_without_requests():
    from adapters.adapter2.cmd import CommandInjectionDetector
    from adapters.adapter2.lfi import LFIDetector
    from adapters.adapter2.ssrf import SSRFDetector
    for detector in (CommandInjectionDetector(), LFIDetector(), SSRFDetector()):
        result = await detector.scan(None)
        assert result.findings == [] and result.candidates == []
        assert result.coverage_outcome == TestOutcome.SKIPPED


@pytest.mark.asyncio
async def test_backend_fingerprint_uses_only_explicit_headers():
    from types import SimpleNamespace
    from adapters.adapter2.backend import BackendFingerprinter
    fingerprinter = BackendFingerprinter()
    signals = await fingerprinter.detect(SimpleNamespace(headers={"Server": "nginx/1.27"}))
    assert len(signals) == 1
    assert signals[0].technology == "nginx"
    assert await fingerprinter.detect(SimpleNamespace(headers={})) == []

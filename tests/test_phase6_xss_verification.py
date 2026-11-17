from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
from dataclasses import replace

import pytest

from adapters.adapter2.budget import BudgetManager
from adapters.adapter2.context import create_context
from adapters.adapter2.framework import DetectionCandidate, Evidence
from adapters.adapter2.models import TestOutcome
from adapters.adapter2.orchestrator import AssessmentOrchestrator
from adapters.adapter2.request import RequestConfig, RequestEngine
from adapters.adapter2.scope import ScopeEngine
from adapters.adapter2.xss import XSSDetector
from adapters.adapter2.xss_verification import (
    XSSVerificationOutcome,
    XSSVerifier,
    candidate_fingerprint,
)
from core_engine import Finding, FindingsPipeline, Severity
from reporting.reporter import Reporter
from tests.local_vulnerable_app import start_server


def _phase6_candidate(target, marker="AILOOKREFLECT" + "a" * 32, parameter="input"):
    evidence = Evidence(
        request_url=f"{target}?{parameter}={marker}", request_method="GET",
        request_headers={}, request_body=None, response_status=200,
        response_headers={"content-type": "text/html; charset=utf-8"},
        response_body_snippet=f"<html><body>{marker}</body></html>",
        matched_signature=marker, elapsed_ms=1,
        contextual_analysis=(
            "phase6_reflection_marker_v1; response_content_type=text/html; "
            "reflection_context=HTML_BODY; "
            f"marker_sha256={hashlib.sha256(marker.encode()).hexdigest()}"
        ),
    )
    return DetectionCandidate(
        finding_type="XSS", target=target, parameter=parameter, method="GET",
        technique="reflected-inert-marker-v1", confidence=0.5,
        evidence=[evidence], reason="controlled marker reflection",
        verification_required="browser execution instrumentation",
    )


@pytest.fixture
async def xss_lab(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    server = start_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    state = server.RequestHandlerClass.state
    scope = ScopeEngine(
        allowed_hosts={host},
        allowed_schemes={"http"},
        allowed_ports={port},
        allowed_path_prefixes=("/",),
        allowed_methods={"GET"},
    )

    async def resolver(name, requested_port):
        state["resolver_calls"].append(name)
        assert name == host and requested_port == port
        return [host]

    engine = RequestEngine(
        scope,
        config=RequestConfig(
            allow_private_ips=True,
            follow_redirects=False,
            max_response_bytes=1024 * 1024,
            read_timeout=5.0,
        ),
        resolver=resolver,
    )
    base = f"http://{host}:{port}"
    pipelines = []

    def make_assessment(path, scan_id, *, budget_limit=50, read_timeout=5.0, max_response_bytes=1024 * 1024):
        budget = BudgetManager(budget_limit)
        context = create_context(
            project_id="phase6-project",
            scan_id=scan_id,
            scan_date="2026-11-17T12:00:00Z",
            target_url=f"{base}{path}",
            scope=scope,
            request_engine=engine,
            budget_manager=budget,
        )
        pipeline = FindingsPipeline(
            db_name=str(tmp_path / f"{scan_id}.sqlite"), enable_ai=False,
        )
        pipelines.append(pipeline)
        orchestrator = AssessmentOrchestrator(context, pipeline, Reporter())
        detector = XSSDetector(
            engine,
            scope,
            max_concurrent_requests=2,
            budget_manager=budget,
            scan_id=scan_id,
        )
        return orchestrator, pipeline, detector, budget

    try:
        yield {
            "base": base,
            "scope": scope,
            "engine": engine,
            "state": state,
            "make_assessment": make_assessment,
        }
    finally:
        for pipeline in pipelines:
            await pipeline.close()
        await engine.aclose()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        try:
            os.unlink(server.db_path)
        except FileNotFoundError:
            pass


@pytest.mark.asyncio
async def test_real_chromium_executes_reflected_proof_and_promotes_exact_candidate(xss_lab, tmp_path):
    orchestrator, pipeline, detector, budget = xss_lab["make_assessment"](
        "/reflect", "phase6-positive",
    )
    reports = await orchestrator.assess_xss(detector, {"input": "unused-original-value"})

    assert len(reports) == 1
    report = reports[0]
    assert report.outcome == XSSVerificationOutcome.VERIFIED, report.model_dump(mode="json")
    assert report.reflection_observed is True
    assert report.context == "HTML_BODY"
    assert report.browser_started is True
    assert report.isolated_context is True
    assert report.headless is True
    assert report.sandbox_enabled is True
    assert report.network_controls_enforced is True
    assert report.proxy_disabled is True
    assert report.browser_dns_fallback_blocked is True
    assert report.websockets_blocked is True
    assert report.service_workers_disabled is True
    assert report.downloads_disabled is True
    assert report.payload_reflected_as_script is True
    assert report.browser_execution_observed is True
    assert report.proof_token_match is True
    assert report.proof_token_sha256
    assert report.request_telemetry_complete is True
    assert report.cleanup_completed is True
    assert report.candidate_fingerprint
    assert report.request_count == len(report.requests)
    assert report.request_engine_exchange_count == sum(
        1 for item in report.requests if item.request_engine_used
    )
    assert report.budget_reservation_count == sum(
        1 for item in report.requests if item.budget_reserved
    )
    assert all(
        item.request_engine_used == item.budget_reserved
        for item in report.requests if item.kind == "http" and item.scope_allowed
    )
    assert all("input=%5BREDACTED%5D" in item.url for item in report.requests)
    assert budget.used("phase6-positive", f"{xss_lab['base']}/reflect") == (
        1 + report.budget_reservation_count
    )

    rendered_path = tmp_path / "phase6-positive.json"
    assessment = await orchestrator.finalize(str(rendered_path))
    assert len(assessment.findings) == 1
    assert assessment.candidates == []
    finding = assessment.findings[0]
    assert finding.type == "XSS"
    assert finding.parameter == "input"
    assert finding.confidence == report.candidate_confidence
    assert finding.observation_status.value == "PRESENT"
    assert finding.requires_human_review is True
    assert "token_sha256=" in finding.evidence[-1]
    payload = json.loads(rendered_path.read_text(encoding="utf-8"))
    assert payload["xss_verification_reports"][0]["outcome"] == "VERIFIED"
    assert payload["findings"][0]["type"] == "XSS"
    await pipeline.close()


@pytest.mark.parametrize(
    "path",
    ["/xss/escaped", "/csp-strict", "/xss/mismatch"],
)
@pytest.mark.asyncio
async def test_browser_execution_without_exact_current_proof_does_not_confirm(xss_lab, path):
    scan_id = f"phase6-negative-{path.rsplit('/', 1)[-1]}"
    orchestrator, pipeline, detector, _ = xss_lab["make_assessment"](path, scan_id)
    reports = await orchestrator.assess_xss(detector, {"input": "not-used"})
    assert reports[0].outcome == XSSVerificationOutcome.NOT_VERIFIED
    assert reports[0].proof_token_match is False
    assert reports[0].request_telemetry_complete is True
    if path == "/csp-strict":
        assert reports[0].payload_reflected_as_script is True
    assessment = await orchestrator.finalize()
    assert assessment.findings == []
    assert len(assessment.candidates) == 1
    assert assessment.coverage_outcome == TestOutcome.INCONCLUSIVE
    await pipeline.close()


@pytest.mark.parametrize(
    "path,expected_context",
    [
        ("/xss/json", "UNKNOWN"),
        ("/xss/attribute", "HTML_ATTRIBUTE"),
        ("/xss/script-string", "JAVASCRIPT_CODE"),
    ],
)
@pytest.mark.asyncio
async def test_json_and_unsupported_contexts_remain_inconclusive(xss_lab, path, expected_context):
    orchestrator, pipeline, detector, _ = xss_lab["make_assessment"](
        path, f"phase6-context-{path.rsplit('/', 1)[-1]}",
    )
    reports = await orchestrator.assess_xss(detector, {"input": "unused"})
    assert reports[0].outcome == XSSVerificationOutcome.INCONCLUSIVE
    assert reports[0].context == expected_context
    assert reports[0].browser_started is False
    assessment = await orchestrator.finalize()
    assert assessment.findings == []
    assert len(assessment.candidates) == 1
    await pipeline.close()


@pytest.mark.asyncio
async def test_out_of_scope_fetch_and_websocket_are_blocked_and_accounted(xss_lab):
    orchestrator, pipeline, detector, _ = xss_lab["make_assessment"](
        "/xss/resources", "phase6-network-blocks",
    )
    reports = await orchestrator.assess_xss(detector, {"input": "unused"})
    report = reports[0]
    assert report.outcome == XSSVerificationOutcome.VERIFIED
    blocked_http = [
        item for item in report.requests
        if item.kind == "http" and "outside.invalid" in item.url
    ]
    blocked_ws = [item for item in report.requests if item.kind == "websocket"]
    assert blocked_http and all(item.scope_allowed is False for item in blocked_http)
    assert blocked_ws and all(item.disposition == "blocked" for item in blocked_ws)
    assert all(item.request_engine_used is False for item in blocked_http)
    assert xss_lab["state"]["resolver_calls"] == []
    assert report.request_telemetry_complete is True
    assert report.cleanup_completed is True
    await orchestrator.finalize()
    await pipeline.close()


@pytest.mark.asyncio
async def test_worker_fetch_uses_scope_and_budget_boundary(xss_lab):
    orchestrator, pipeline, detector, _ = xss_lab["make_assessment"](
        "/xss/worker", "phase6-worker",
    )
    report = (await orchestrator.assess_xss(detector, {"input": "unused"}))[0]
    worker_requests = [
        item for item in report.requests
        if item.kind == "http" and "xss-worker" in item.url
    ]
    assert worker_requests, report.model_dump(mode="json")
    assert all(item.scope_allowed is False for item in worker_requests)
    assert all(item.request_engine_used is False for item in worker_requests)
    assert xss_lab["state"]["resolver_calls"] == []
    await orchestrator.finalize()
    await pipeline.close()


@pytest.mark.asyncio
async def test_non_http_frame_navigation_fails_closed(xss_lab):
    orchestrator, pipeline, detector, _ = xss_lab["make_assessment"](
        "/xss/non-http", "phase6-non-http",
    )
    report = (await orchestrator.assess_xss(detector, {"input": "unused"}))[0]
    assert report.outcome == XSSVerificationOutcome.INCONCLUSIVE
    assert report.request_telemetry_complete is False
    assert report.cleanup_completed is True
    non_http = [item for item in report.requests if item.kind == "non-http"]
    assert non_http
    assert all(item.scope_allowed is False for item in non_http)
    assert all("data:" not in item.url.lower() for item in non_http)
    assert all(item.url != "[DATA_NAVIGATION]" for item in non_http)
    assert xss_lab["state"]["resolver_calls"] == []
    assessment = await orchestrator.finalize()
    assert assessment.findings == []
    await pipeline.close()


@pytest.mark.asyncio
async def test_cross_origin_redirect_is_scope_checked_and_never_followed(xss_lab):
    orchestrator, pipeline, detector, _ = xss_lab["make_assessment"](
        "/xss/redirect-outside", "phase6-redirect-outside",
    )
    reports = await orchestrator.assess_xss(detector, {"input": "unused"})
    report = reports[0]
    assert report.outcome == XSSVerificationOutcome.INCONCLUSIVE
    assert len(report.redirects) == 1
    assert report.redirects[0].scope_allowed is False
    assert report.redirects[0].followed is False
    assert report.request_engine_exchange_count == 1
    assert xss_lab["state"]["resolver_calls"] == []
    await orchestrator.finalize()
    await pipeline.close()


@pytest.mark.asyncio
async def test_authorized_redirect_is_still_stopped_without_browser_auto_follow(xss_lab):
    orchestrator, pipeline, detector, _ = xss_lab["make_assessment"](
        "/xss/redirect-authorized", "phase6-redirect-authorized",
    )
    before = xss_lab["state"]["request_count"]
    report = (await orchestrator.assess_xss(detector, {"input": "unused"}))[0]
    assert report.outcome == XSSVerificationOutcome.INCONCLUSIVE
    assert report.redirects[0].scope_allowed is True
    assert report.redirects[0].followed is False
    assert xss_lab["state"]["request_count"] == before + 2
    await orchestrator.finalize()
    await pipeline.close()


@pytest.mark.asyncio
async def test_browser_subresource_exchanges_consume_shared_budget(xss_lab):
    scan_id = "phase6-shared-budget"
    orchestrator, pipeline, detector, budget = xss_lab["make_assessment"](
        "/xss/same-origin-resource", scan_id, budget_limit=2,
    )
    report = (await orchestrator.assess_xss(detector, {"input": "unused"}))[0]
    assert report.outcome == XSSVerificationOutcome.INCONCLUSIVE
    assert report.request_engine_exchange_count == sum(
        1 for item in report.requests if item.request_engine_used
    )
    assert report.budget_reservation_count == sum(
        1 for item in report.requests if item.budget_reserved
    )
    assert any("budget" in item.reason.lower() for item in report.requests)
    assert budget.used(scan_id, f"{xss_lab['base']}/xss/same-origin-resource") == 2
    assessment = await orchestrator.finalize()
    assert assessment.findings == []
    await pipeline.close()


@pytest.mark.asyncio
async def test_browser_timeout_is_inconclusive_and_cleans_up(xss_lab):
    orchestrator, pipeline, detector, _ = xss_lab["make_assessment"](
        "/xss/slow-proof", "phase6-timeout",
    )
    report = (await orchestrator.assess_xss(detector, {"input": "unused"}))[0]
    assert report.outcome == XSSVerificationOutcome.INCONCLUSIVE
    assert report.timed_out is True
    assert report.cleanup_completed is True
    assessment = await orchestrator.finalize()
    assert assessment.findings == []
    await pipeline.close()


@pytest.mark.asyncio
async def test_truncated_browser_response_is_inconclusive(xss_lab):
    orchestrator, pipeline, detector, _ = xss_lab["make_assessment"](
        "/xss/large-proof", "phase6-truncated",
    )
    report = (await orchestrator.assess_xss(detector, {"input": "unused"}))[0]
    assert report.outcome == XSSVerificationOutcome.INCONCLUSIVE
    assert report.truncated is True
    assert report.cleanup_completed is True
    assert await orchestrator.finalize() is not None
    await pipeline.close()


@pytest.mark.asyncio
async def test_stale_token_from_prior_context_cannot_confirm_new_attempt(xss_lab):
    first, pipeline1, detector1, _ = xss_lab["make_assessment"](
        "/xss/stale-token", "phase6-stale-one",
    )
    first_report = (await first.assess_xss(detector1, {"input": "unused"}))[0]
    assert first_report.outcome == XSSVerificationOutcome.VERIFIED
    await first.finalize()
    await pipeline1.close()

    second, pipeline2, detector2, _ = xss_lab["make_assessment"](
        "/xss/stale-token", "phase6-stale-two",
    )
    second_report = (await second.assess_xss(detector2, {"input": "unused"}))[0]
    assert second_report.outcome == XSSVerificationOutcome.NOT_VERIFIED
    assert second_report.browser_execution_observed is True
    assert second_report.proof_token_match is False
    assert second_report.proof_token_sha256 != first_report.proof_token_sha256
    assert second_report.cleanup_completed is True
    assessment = await second.finalize()
    assert assessment.findings == []
    assert len(assessment.candidates) == 1
    await pipeline2.close()


@pytest.mark.asyncio
async def test_browser_startup_failure_is_blocked_and_never_promotes(xss_lab, monkeypatch):
    orchestrator, pipeline, detector, _ = xss_lab["make_assessment"](
        "/reflect", "phase6-startup-failure",
    )
    from playwright.async_api import BrowserType

    async def fail_start(self, *args, **kwargs):
        raise OSError("simulated browser runtime unavailable")

    monkeypatch.setattr(BrowserType, "launch", fail_start)
    report = (await orchestrator.assess_xss(detector, {"input": "unused"}))[0]
    assert report.outcome == XSSVerificationOutcome.BLOCKED
    assert report.browser_started is False
    assert report.proof_token_match is False
    assert report.cleanup_completed is True
    assessment = await orchestrator.finalize()
    assert assessment.findings == []
    await pipeline.close()


@pytest.mark.asyncio
async def test_cleanup_failure_never_promotes_even_after_exact_proof(xss_lab, monkeypatch):
    orchestrator, pipeline, detector, _ = xss_lab["make_assessment"](
        "/reflect", "phase6-cleanup-failure",
    )
    from playwright.async_api import BrowserContext

    async def fail_context_close(self, *args, **kwargs):
        raise RuntimeError("simulated context cleanup failure")

    monkeypatch.setattr(BrowserContext, "close", fail_context_close)
    report = (await orchestrator.assess_xss(detector, {"input": "unused"}))[0]
    assert report.browser_execution_observed is True
    assert report.proof_token_match is True
    assert report.cleanup_completed is False
    assert report.outcome == XSSVerificationOutcome.INCONCLUSIVE
    assessment = await orchestrator.finalize()
    assert assessment.findings == []
    assert len(assessment.candidates) == 1
    await pipeline.close()


@pytest.mark.asyncio
async def test_xss_findings_cannot_bypass_matching_verification_report(xss_lab):
    orchestrator, pipeline, detector, _ = xss_lab["make_assessment"](
        "/reflect", "phase6-promotion-gate",
    )
    finding = Finding(
        type="CROSS_SITE_SCRIPTING", target=f"{xss_lab['base']}/reflect",
        parameter="input", method="GET", severity=Severity.HIGH,
        confidence=0.99, source="untrusted", evidence=["fabricated"],
    )
    from adapters.adapter2.framework import AdapterScanResult

    with pytest.raises(ValueError, match="assess_xss"):
        orchestrator.add_result(
            "UNTRUSTED",
            AdapterScanResult([finding], [], TestOutcome.PRESENT, "fabricated"),
        )
    await pipeline.close()


@pytest.mark.asyncio
async def test_matching_report_cannot_promote_a_different_candidate(xss_lab):
    orchestrator, pipeline, detector, _ = xss_lab["make_assessment"](
        "/reflect", "phase6-candidate-mismatch",
    )
    report = (await orchestrator.assess_xss(detector, {"input": "unused"}))[0]
    assert report.outcome == XSSVerificationOutcome.VERIFIED
    other = DetectionCandidate(
        finding_type="XSS",
        target=f"{xss_lab['base']}/reflect",
        parameter="other",
        method="GET",
        technique="reflected-inert-marker-v1",
        confidence=report.candidate_confidence,
        evidence=(),
        reason="different input identity",
        verification_required="browser execution instrumentation",
    )
    with pytest.raises(ValueError, match="matching VERIFIED"):
        AssessmentOrchestrator._finding_from_verified_xss_candidate(other, report)
    await orchestrator.finalize()
    await pipeline.close()


@pytest.mark.asyncio
async def test_verifier_is_single_use_to_prevent_state_leakage(xss_lab):
    target = f"{xss_lab['base']}/reflect"
    marker = "AILOOKREFLECT" + "a" * 32
    candidate = _phase6_candidate(target, marker)
    budget = BudgetManager(10)
    verifier = XSSVerifier(
        xss_lab["engine"], xss_lab["scope"], budget_manager=budget,
        scan_id="phase6-single-use",
    )
    first = await verifier.verify(candidate)
    assert first.outcome == XSSVerificationOutcome.VERIFIED
    assert first.candidate_fingerprint == candidate_fingerprint(candidate)
    with pytest.raises(RuntimeError, match="single-use"):
        await verifier.verify(candidate)


@pytest.mark.asyncio
async def test_marker_evidence_hash_must_match_before_browser_start(xss_lab):
    target = f"{xss_lab['base']}/reflect"
    candidate = _phase6_candidate(target)
    evidence = replace(
        candidate.evidence[0],
        contextual_analysis=(
            "phase6_reflection_marker_v1; response_content_type=text/html; "
            "reflection_context=HTML_BODY; marker_sha256=" + "0" * 64
        ),
    )
    candidate = replace(candidate, evidence=(evidence,))
    budget = BudgetManager(10)
    verifier = XSSVerifier(
        xss_lab["engine"], xss_lab["scope"], budget_manager=budget,
        scan_id="phase6-marker-evidence",
    )
    report = await verifier.verify(candidate)
    assert report.outcome == XSSVerificationOutcome.NOT_TESTED
    assert report.browser_started is False
    assert report.request_count == 0
    assert budget.used("phase6-marker-evidence", target) == 0


@pytest.mark.parametrize(
    "answers",
    [[], ["93.184.216.34", "127.0.0.1"]],
    ids=["dns-empty", "dns-rebinding-mixed-addresses"],
)
@pytest.mark.asyncio
async def test_dns_failures_and_rebinding_fail_closed(xss_lab, answers):
    calls = []
    scope = ScopeEngine(
        allowed_hosts={"rebind.test"}, allowed_schemes={"http"},
        allowed_ports={80}, allowed_path_prefixes=("/",),
        allowed_methods={"GET"},
    )

    async def resolver(name, port):
        calls.append((name, port))
        return answers

    engine = RequestEngine(
        scope,
        config=RequestConfig(allow_private_ips=False, follow_redirects=False),
        resolver=resolver,
    )
    try:
        candidate = _phase6_candidate("http://rebind.test/reflect")
        budget = BudgetManager(10)
        verifier = XSSVerifier(
            engine, scope, budget_manager=budget, scan_id="phase6-dns-fail",
        )
        report = await verifier.verify(candidate)
        assert report.outcome == XSSVerificationOutcome.INCONCLUSIVE
        assert calls == [("rebind.test", 80)]
        assert report.request_count == 1
        assert report.request_engine_exchange_count == 1
        assert report.requests[0].budget_reserved is True
        assert report.requests[0].pinned_ip is None
        assert report.proof_token_match is False
        assert report.cleanup_completed is True
    finally:
        await engine.aclose()


@pytest.mark.asyncio
async def test_concurrent_browser_attempts_share_request_concurrency_limit(xss_lab):
    scan_id = "phase6-concurrent"
    budget = BudgetManager(20)
    target = f"{xss_lab['base']}/xss/concurrent-slow"
    candidates = [
        _phase6_candidate(target, "AILOOKREFLECT" + str(index) * 32)
        for index in (1, 2)
    ]
    verifiers = [
        XSSVerifier(
            xss_lab["engine"], xss_lab["scope"], budget_manager=budget,
            scan_id=scan_id, max_concurrent_requests=1,
        )
        for _ in candidates
    ]
    reports = await asyncio.gather(*(
        verifier.verify(candidate)
        for verifier, candidate in zip(verifiers, candidates)
    ))
    assert all(report.outcome == XSSVerificationOutcome.VERIFIED for report in reports)
    assert xss_lab["state"]["max_active_slow"] == 1
    assert reports[0].proof_token_sha256 != reports[1].proof_token_sha256
    assert all(report.cleanup_completed for report in reports)

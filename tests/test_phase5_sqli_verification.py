from __future__ import annotations

import asyncio
import json
import os
import threading

import pytest

from adapters.adapter2.budget import BudgetManager
from adapters.adapter2.context import create_context
from adapters.adapter2.framework import AdapterScanResult, DetectionCandidate
from adapters.adapter2.models import TestOutcome
from adapters.adapter2.orchestrator import AssessmentOrchestrator
from adapters.adapter2.redaction import configure_secrets
from adapters.adapter2.request import RequestConfig, RequestEngine
from adapters.adapter2.scope import ScopeEngine
from adapters.adapter2.sqli import SQLiDetector
from adapters.adapter2.sqli_verification import (
    SQLiVerificationOutcome,
    SQLiValueContext,
    SQLiVerifier,
    classify_original_value,
)
from core_engine import (
    Finding,
    FindingStatus,
    FindingsPipeline,
    ObservationStatus,
    Severity,
)
from reporting.reporter import Reporter
from tests.local_vulnerable_app import start_server


@pytest.fixture
async def local_target():
    server = start_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    scope = ScopeEngine(
        allowed_hosts={host},
        allowed_schemes={"http"},
        allowed_ports={port},
        allowed_path_prefixes=("/",),
        allowed_methods={"GET"},
    )

    async def resolver(name, requested_port):
        server.RequestHandlerClass.state["resolver_calls"].append(name)
        assert name == host and requested_port == port
        return [host]

    def make_engine(
        *, follow_redirects=False, max_response_bytes=1024 * 1024, read_timeout=10.0
    ):
        return RequestEngine(
            scope,
            config=RequestConfig(
                allow_private_ips=True,
                follow_redirects=follow_redirects,
                max_response_bytes=max_response_bytes,
                read_timeout=read_timeout,
            ),
            resolver=resolver,
        )

    engine = make_engine()
    try:
        yield f"http://{host}:{port}", scope, engine, server, make_engine
    finally:
        await engine.aclose()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        try:
            os.unlink(server.db_path)
        except FileNotFoundError:
            pass


def _candidate(target: str, parameter: str = "id", technique: str = "error_based"):
    return DetectionCandidate(
        finding_type="SQL_INJECTION",
        target=target,
        parameter=parameter,
        method="GET",
        technique=technique,
        confidence=0.73,
        evidence=(),
        reason="controlled test candidate",
        verification_required="verified vulnerable database behavior",
    )


def _orchestrator(base, target, scope, engine, budget, scan_id, tmp_path, *, enable_ai=True):
    context = create_context(
        project_id="phase5-project",
        scan_id=scan_id,
        scan_date="2026-11-17T12:00:00Z",
        target_url=target,
        scope=scope,
        request_engine=engine,
        budget_manager=budget,
    )
    pipeline = FindingsPipeline(
        db_name=str(tmp_path / f"{scan_id}.sqlite"), enable_ai=enable_ai
    )
    return AssessmentOrchestrator(context, pipeline, Reporter()), pipeline


def _detector(engine, scope, budget, scan_id):
    return SQLiDetector(
        engine,
        scope,
        budget_manager=budget,
        scan_id=scan_id,
        enable_time_based=False,
        enable_union_based=False,
    )


def _verifier(engine, scope, budget, scan_id):
    return SQLiVerifier(engine, scope, budget_manager=budget, scan_id=scan_id)


async def _async_identity(finding):
    return finding


@pytest.mark.parametrize(
    "value,expected",
    [
        ("0", SQLiValueContext.NUMERIC),
        ("-12", SQLiValueContext.NUMERIC),
        ("1.25", SQLiValueContext.NUMERIC),
        ("fixtureuser", SQLiValueContext.SINGLE_QUOTED_STRING),
        ("user_7", SQLiValueContext.SINGLE_QUOTED_STRING),
    ],
)
def test_conservative_original_value_grammars(value, expected):
    assert classify_original_value(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "1 OR 1",
        "1 UNION SELECT",
        "1; SELECT",
        "1--",
        "1/*comment*/",
        "1 AND 1=1",
        "1' OR '1'='1",
        "' OR '1'='1",
        "1 + 2",
        "1e3",
        "",
        " 1",
        "fixture-user",
        "OR",
        "SELECT",
        "NULL",
    ],
)
async def test_unsafe_original_values_make_zero_requests(local_target, value):
    base, scope, engine, server, _ = local_target
    budget = BudgetManager(default_max_requests=100)
    verifier = _verifier(engine, scope, budget, "invalid-input")
    candidate = _candidate(f"{base}/sqli/one-empty")

    report = await verifier.verify(candidate, value)

    assert report.outcome == SQLiVerificationOutcome.NOT_TESTED
    assert report.request_count == 0
    assert budget.used("invalid-input", candidate.target) == 0
    assert server.RequestHandlerClass.state["request_count"] == 0


@pytest.mark.asyncio
async def test_numeric_sqlite_candidate_is_verified_and_promoted_only_with_matching_report(
    local_target, tmp_path, monkeypatch
):
    base, scope, engine, server, _ = local_target
    monkeypatch.chdir(tmp_path)
    target = f"{base}/sqli/sqlite-vulnerable"
    scan_id = "phase5-numeric-positive"
    budget = BudgetManager(default_max_requests=100)
    orchestrator, pipeline = _orchestrator(base, target, scope, engine, budget, scan_id, tmp_path)
    ai_types = []

    async def record_ai(finding):
        ai_types.append(finding.type)
        return finding

    pipeline.analyze_with_limit = record_ai
    detector = _detector(engine, scope, budget, scan_id)
    detected_candidates = []
    create_candidate = detector.make_candidate

    def remember_candidate(*args, **kwargs):
        candidate = create_candidate(*args, **kwargs)
        detected_candidates.append(candidate)
        return candidate

    detector.make_candidate = remember_candidate
    detector.scan_parameter = lambda *args, **kwargs: pytest.fail(
        "Phase 5 must not call the legacy SQLi probe path"
    )
    reports = await orchestrator.assess_sqli(detector, {"id": "1"})
    assert len(reports) == 1
    report = reports[0]
    assert report.outcome == SQLiVerificationOutcome.VERIFIED
    assert report.context == SQLiValueContext.NUMERIC.value
    assert report.request_count == 9
    assert report.completed_repetitions == 3
    assert report.baseline_matches_true is True
    assert report.false_differs is True
    assert report.additional_verification_requirements == "verified vulnerable database behavior"
    assert all(sample.completed_exchange and sample.body_is_decoded for sample in report.samples)
    assert {sample.status_code for sample in report.samples} == {200}
    assert len(detected_candidates) == 1
    assert server.RequestHandlerClass.state["request_count"] == 18
    assert all(" OR " not in value.upper() for value in server.RequestHandlerClass.state["request_values"])
    assert all("'" not in value for value in server.RequestHandlerClass.state["request_values"])

    # A valid report for candidate A must not authorize a different candidate B.
    mismatched = _candidate(target, parameter="other_id", technique="boolean_based")
    orchestrator.add_result(
        "SQLI",
        AdapterScanResult([], [mismatched], TestOutcome.INCONCLUSIVE,
                          "independent candidate", 0),
        target=target,
        test_family="SQLI",
    )
    with pytest.raises(ValueError, match="matching VERIFIED report"):
        orchestrator._finding_from_verified_candidate(mismatched, report)

    # A later ordinary adapter submission cannot reintroduce the promoted candidate.
    orchestrator.add_result(
        "SQLI",
        AdapterScanResult([], [detected_candidates[0]], TestOutcome.INCONCLUSIVE,
                          "candidate duplicate", 1),
        target=target,
        test_family="SQLI",
    )
    assessment = await orchestrator.finalize(str(tmp_path / "numeric-assessment.json"))
    persisted = await pipeline.db_manager.get_active_findings("phase5-project")
    await pipeline.close()

    assert len(assessment.findings) == len(persisted) == 1
    finding = assessment.findings[0]
    assert finding.type == "SQL_INJECTION"
    assert finding.observation_status == ObservationStatus.PRESENT
    assert finding.status == FindingStatus.OPEN
    assert finding.confidence == detected_candidates[0].confidence
    assert finding.confidence != 0.95
    assert finding.fingerprint == report.finding_fingerprint == persisted[0].fingerprint
    assert [candidate.parameter for candidate in assessment.candidates] == ["other_id"]
    assert all(finding.parameter != "other_id" for finding in assessment.findings)
    assert assessment.verification_reports[0].candidate_fingerprint == report.candidate_fingerprint
    assert ai_types == ["SQL_INJECTION"]
    assert server.RequestHandlerClass.state["request_count"] > report.request_count


@pytest.mark.asyncio
async def test_single_quoted_sqlite_candidate_is_verified(local_target, tmp_path, monkeypatch):
    base, scope, engine, server, _ = local_target
    monkeypatch.chdir(tmp_path)
    target = f"{base}/sqli/sqlite-string-vulnerable"
    scan_id = "phase5-string-positive"
    budget = BudgetManager(default_max_requests=100)
    orchestrator, pipeline = _orchestrator(base, target, scope, engine, budget, scan_id, tmp_path)
    orchestrator.pipeline.analyze_with_limit = _async_identity
    reports = await orchestrator.assess_sqli(
        _detector(engine, scope, budget, scan_id), {"name": "fixtureuser"}
    )
    assessment = await orchestrator.finalize()
    await pipeline.close()

    assert reports[0].outcome == SQLiVerificationOutcome.VERIFIED, (
        reports[0].reason,
        [(sample.group, sample.status_code) for sample in reports[0].samples],
    )
    assert reports[0].context == SQLiValueContext.SINGLE_QUOTED_STRING.value
    assert reports[0].request_count == 9
    assert len(assessment.findings) == 1
    assert assessment.findings[0].parameter == "name"
    assert all(" OR " not in value.upper() for value in server.RequestHandlerClass.state["request_values"])
    assert any(" AND '1'='1" in value for value in server.RequestHandlerClass.state["request_values"])


@pytest.mark.asyncio
async def test_complete_boolean_sequence_without_differential_retains_candidate(
    local_target, tmp_path, monkeypatch
):
    base, scope, engine, _, _ = local_target
    monkeypatch.chdir(tmp_path)
    target = f"{base}/sqli/candidate-only"
    scan_id = "phase5-not-confirmed"
    budget = BudgetManager(default_max_requests=100)
    orchestrator, pipeline = _orchestrator(base, target, scope, engine, budget, scan_id, tmp_path)
    ai_types = []

    async def record_ai(finding):
        ai_types.append(finding.type)
        return finding

    pipeline.analyze_with_limit = record_ai
    configure_secrets(["fixture-secret"])
    detector = _detector(engine, scope, budget, scan_id)
    prior_candidate = _candidate(target, "id", "error_based")

    async def seeded_scan(url, parameter, original_value):
        return AdapterScanResult(
            [], [prior_candidate], TestOutcome.INCONCLUSIVE,
            "controlled prior candidate", 0,
        )

    monkeypatch.setattr(detector, "scan_parameter_safe", seeded_scan)
    try:
        reports = await orchestrator.assess_sqli(
            detector, {"id": "1"}
        )
        report_path = tmp_path / "not-confirmed.json"
        assessment = await orchestrator.finalize(str(report_path))
        rendered = report_path.read_text(encoding="utf-8")
    finally:
        configure_secrets([])
        await pipeline.close()

    assert reports[0].outcome == SQLiVerificationOutcome.NOT_CONFIRMED
    assert reports[0].completed_repetitions == 3
    assert reports[0].request_count == 9
    assert assessment.findings == []
    assert len(assessment.candidates) == 1
    verification_coverage = [
        item for item in assessment.coverage_records
        if item.test_family == "SQLI_VERIFICATION"
    ]
    assert [item.outcome for item in verification_coverage] == [TestOutcome.ABSENT]
    assert ai_types == []
    assert "fixture-secret" not in rendered
    payload = json.loads(rendered)
    assert payload["verification_reports"][0]["outcome"] == "NOT_CONFIRMED"
    assert payload["verification_reports"][0]["additional_verification_requirements"] == prior_candidate.verification_required
    assert payload["candidates"][0]["candidate_fingerprint"] == reports[0].candidate_fingerprint
    assert payload["candidates"][0]["verification_outcome"] == "NOT_CONFIRMED"


@pytest.mark.asyncio
async def test_parameterized_sqlite_candidate_is_not_confirmed_or_promoted(
    local_target, tmp_path, monkeypatch
):
    base, scope, engine, server, _ = local_target
    monkeypatch.chdir(tmp_path)
    target = f"{base}/sqli/sqlite-safe"
    scan_id = "phase5-parameterized-negative"
    budget = BudgetManager(default_max_requests=100)
    orchestrator, pipeline = _orchestrator(base, target, scope, engine, budget, scan_id, tmp_path)
    orchestrator.pipeline.analyze_with_limit = _async_identity
    detector = _detector(engine, scope, budget, scan_id)
    candidate = _candidate(target, parameter="id", technique="boolean_based")

    # Seed the candidate as a prior detector observation, then exercise the
    # production orchestration verifier against the real parameterized SQLite route.
    async def seeded_scan(url, parameter, original_value):
        assert (url, parameter, original_value) == (target, "id", "1")
        return AdapterScanResult(
            [], [candidate], TestOutcome.INCONCLUSIVE,
            "controlled prior Boolean candidate", 1,
        )

    monkeypatch.setattr(detector, "scan_parameter_safe", seeded_scan)
    reports = await orchestrator.assess_sqli(detector, {"id": "1"})
    assessment = await orchestrator.finalize()
    await pipeline.close()

    assert len(reports) == 1
    assert reports[0].outcome == SQLiVerificationOutcome.NOT_CONFIRMED
    assert reports[0].request_count == 9
    assert reports[0].baseline_matches_true is False
    assert reports[0].false_differs is False
    assert assessment.findings == []
    assert len(assessment.candidates) == 1
    assert assessment.candidates[0].parameter == "id"
    verification_coverage = [
        item for item in assessment.coverage_records
        if item.test_family == "SQLI_VERIFICATION"
    ]
    assert [item.outcome for item in verification_coverage] == [TestOutcome.ABSENT]
    assert server.RequestHandlerClass.state["request_count"] == 9


@pytest.mark.asyncio
async def test_exactly_one_empty_sample_makes_complete_sequence_inconclusive(local_target):
    base, scope, engine, server, _ = local_target
    budget = BudgetManager(default_max_requests=100)
    candidate = _candidate(f"{base}/sqli/one-empty", parameter="input")
    report = await _verifier(engine, scope, budget, "one-empty").verify(candidate, "fixture")

    assert report.outcome == SQLiVerificationOutcome.INCONCLUSIVE
    assert report.request_count == 9
    assert report.completed_repetitions == 3
    assert len(report.samples) == 9
    assert sum(sample.empty for sample in report.samples) == 1
    assert sum(sample.completed_exchange for sample in report.samples) == 9
    assert server.RequestHandlerClass.state["request_count"] == 9


@pytest.mark.asyncio
async def test_all_empty_samples_are_inconclusive(local_target):
    base, scope, engine, _, _ = local_target
    candidate = _candidate(f"{base}/sqli/empty-all", parameter="input")
    report = await _verifier(engine, scope, BudgetManager(100), "all-empty").verify(candidate, "fixture")

    assert report.outcome == SQLiVerificationOutcome.INCONCLUSIVE
    assert len(report.samples) == 9
    assert all(sample.empty for sample in report.samples)


@pytest.mark.asyncio
async def test_reflection_only_is_not_verified_and_dynamic_content_is_inconclusive(local_target):
    base, scope, engine, _, _ = local_target
    verifier = _verifier(engine, scope, BudgetManager(100), "reflection")
    reflected = await verifier.verify(_candidate(f"{base}/reflect", "input"), "hello")
    encoded_reflection = await verifier.verify(
        _candidate(f"{base}/reflect-encoded", "input"), "hello"
    )
    false_only_reflection = await verifier.verify(
        _candidate(f"{base}/reflect-false-only", "id"), "1"
    )
    dynamic = await verifier.verify(_candidate(f"{base}/dynamic", "input"), "hello")

    assert reflected.outcome == SQLiVerificationOutcome.INCONCLUSIVE
    assert any(sample.reflection_neutralized for sample in reflected.samples)
    assert any(sample.control_reflection_detected for sample in reflected.samples)
    assert encoded_reflection.outcome == SQLiVerificationOutcome.INCONCLUSIVE
    assert any(sample.control_reflection_detected for sample in encoded_reflection.samples)
    assert false_only_reflection.outcome == SQLiVerificationOutcome.INCONCLUSIVE
    assert false_only_reflection.reason == "a Boolean control expression was reflected in a response"
    assert any(sample.control_reflection_detected for sample in false_only_reflection.samples)
    assert dynamic.outcome == SQLiVerificationOutcome.INCONCLUSIVE
    assert dynamic.reason == "repeated response content was unstable"


@pytest.mark.asyncio
async def test_status_variation_is_inconclusive(local_target):
    base, scope, engine, _, _ = local_target
    report = await _verifier(engine, scope, BudgetManager(100), "status-variation").verify(
        _candidate(f"{base}/sqli/status-variation"), "1"
    )
    assert report.outcome == SQLiVerificationOutcome.INCONCLUSIVE
    assert {sample.status_code for sample in report.samples} == {200, 201}


@pytest.mark.parametrize("path,status", [("status-404", 404), ("status-500", 500)])
@pytest.mark.asyncio
async def test_http_error_statuses_are_never_negative_results(local_target, path, status):
    base, scope, engine, _, _ = local_target
    report = await _verifier(engine, scope, BudgetManager(100), f"http-{status}").verify(
        _candidate(f"{base}/{path}", parameter="input"), "hello"
    )
    assert report.outcome == SQLiVerificationOutcome.INCONCLUSIVE
    assert report.request_count == 9
    assert {sample.status_code for sample in report.samples} == {status}


@pytest.mark.asyncio
async def test_scope_rejection_is_not_tested_before_network(local_target):
    base, _, engine, server, _ = local_target
    port = int(base.rsplit(":", 1)[1])
    denied_scope = ScopeEngine(
        allowed_hosts=set(), allowed_schemes={"http"}, allowed_ports={port},
        allowed_path_prefixes=("/",), allowed_methods={"GET"},
    )
    candidate = _candidate(f"{base}/slow", parameter="input")
    report = await _verifier(engine, denied_scope, BudgetManager(100), "scope-denied").verify(
        candidate, "hello"
    )
    assert report.outcome == SQLiVerificationOutcome.NOT_TESTED
    assert report.request_count == 0
    assert server.RequestHandlerClass.state["request_count"] == 0


@pytest.mark.asyncio
async def test_transport_failure_is_error_without_claiming_absence(local_target):
    base, scope, engine, server, _ = local_target
    await engine.aclose()
    report = await _verifier(engine, scope, BudgetManager(100), "closed-engine").verify(
        _candidate(f"{base}/slow", parameter="input"), "hello"
    )
    assert report.outcome == SQLiVerificationOutcome.ERROR
    assert report.request_count == 1
    assert len(report.samples) == 1
    assert report.samples[0].error_category == "closed"
    assert report.samples[0].completed_exchange is False
    assert server.RequestHandlerClass.state["request_count"] == 0


@pytest.mark.asyncio
async def test_timeout_is_inconclusive(local_target):
    base, scope, _, server, make_engine = local_target
    engine = make_engine(read_timeout=0.01)
    try:
        report = await _verifier(engine, scope, BudgetManager(100), "timeout").verify(
            _candidate(f"{base}/slow", parameter="input"), "hello"
        )
    finally:
        await engine.aclose()
    assert report.outcome == SQLiVerificationOutcome.INCONCLUSIVE
    assert report.request_count == 1
    assert len(report.samples) == 1
    assert report.samples[0].error_category == "timeout"
    assert report.samples[0].completed_exchange is False
    assert server.RequestHandlerClass.state["request_count"] == 1


@pytest.mark.asyncio
async def test_cancellation_propagates_and_cleans_request_tracking(local_target):
    base, scope, engine, server, _ = local_target
    verifier = _verifier(engine, scope, BudgetManager(100), "cancel")
    task = asyncio.create_task(
        verifier.verify(_candidate(f"{base}/slow", parameter="input"), "hello")
    )
    for _ in range(100):
        if server.RequestHandlerClass.state["request_count"]:
            break
        await asyncio.sleep(0.005)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert engine._active == set()


@pytest.mark.asyncio
async def test_concurrent_verifiers_share_scan_concurrency_gate(local_target):
    base, scope, engine, server, _ = local_target
    budget = BudgetManager(100)
    first = SQLiVerifier(
        engine, scope, budget_manager=budget, scan_id="parallel", max_concurrent_requests=1
    )
    second = SQLiVerifier(
        engine, scope, budget_manager=budget, scan_id="parallel", max_concurrent_requests=1
    )
    outcomes = await asyncio.gather(
        first.verify(_candidate(f"{base}/slow", parameter="input"), "hello"),
        second.verify(_candidate(f"{base}/slow", parameter="input"), "hello"),
    )
    assert all(item.outcome == SQLiVerificationOutcome.NOT_CONFIRMED for item in outcomes)
    assert server.RequestHandlerClass.state["max_active_slow"] == 1


@pytest.mark.asyncio
async def test_truncated_response_is_inconclusive(local_target):
    base, scope, _, _, make_engine = local_target
    engine = make_engine(max_response_bytes=128)
    try:
        report = await _verifier(engine, scope, BudgetManager(100), "truncated").verify(
            _candidate(f"{base}/large", parameter="input"), "hello"
        )
    finally:
        await engine.aclose()
    assert report.outcome == SQLiVerificationOutcome.INCONCLUSIVE
    assert report.request_count == 1
    assert report.samples[0].truncated is True


@pytest.mark.asyncio
async def test_undecodable_response_is_inconclusive(local_target):
    base, scope, engine, server, _ = local_target
    report = await _verifier(engine, scope, BudgetManager(100), "undecodable").verify(
        _candidate(f"{base}/undecodable", parameter="input"), "hello"
    )

    assert report.outcome == SQLiVerificationOutcome.INCONCLUSIVE
    assert report.request_count == 1
    assert len(report.samples) == 1
    assert report.samples[0].body_is_decoded is False
    assert server.RequestHandlerClass.state["request_count"] == 1


@pytest.mark.asyncio
async def test_insufficient_initial_budget_is_not_tested_without_network(local_target):
    base, scope, engine, server, _ = local_target
    budget = BudgetManager(default_max_requests=8)
    candidate = _candidate(f"{base}/sqli/one-empty", parameter="input")
    report = await _verifier(engine, scope, budget, "insufficient").verify(candidate, "fixture")

    assert report.outcome == SQLiVerificationOutcome.NOT_TESTED
    assert report.request_count == 0
    assert report.samples == ()
    assert server.RequestHandlerClass.state["request_count"] == 0


@pytest.mark.asyncio
async def test_mid_sequence_budget_exhaustion_is_inconclusive(local_target):
    base, scope, engine, server, _ = local_target

    class ExhaustAfterFirstReservation(BudgetManager):
        def reserve(self, scan_id, url, amount=1):
            key = super().reserve(scan_id, url, amount)
            if self.used(scan_id, url) == 1:
                self.set_limit(scan_id, url, 1)
            return key

    budget = ExhaustAfterFirstReservation(default_max_requests=9)
    candidate = _candidate(f"{base}/sqli/one-empty", parameter="input")
    report = await _verifier(engine, scope, budget, "mid-budget").verify(candidate, "fixture")

    assert report.outcome == SQLiVerificationOutcome.INCONCLUSIVE
    assert report.request_count == 1
    assert server.RequestHandlerClass.state["request_count"] == 1


@pytest.mark.asyncio
async def test_unauthorized_redirect_is_not_followed_and_is_inconclusive(local_target):
    base, scope, _, server, make_engine = local_target
    engine = make_engine(follow_redirects=True)
    try:
        candidate = _candidate(f"{base}/redirect-untrusted", parameter="input")
        report = await _verifier(engine, scope, BudgetManager(100), "redirect").verify(candidate, "hello")
    finally:
        await engine.aclose()

    assert report.outcome == SQLiVerificationOutcome.INCONCLUSIVE
    assert report.request_count == 9
    assert server.RequestHandlerClass.state["request_count"] == 9
    assert "outside.invalid" not in server.RequestHandlerClass.state["resolver_calls"]


@pytest.mark.asyncio
async def test_phase5_verifier_bounds_redirects_to_one_exchange_per_reservation(local_target):
    base, scope, _, server, make_engine = local_target
    engine = make_engine(follow_redirects=True)
    budget = BudgetManager(9)
    try:
        candidate = _candidate(f"{base}/redirect-authorized", parameter="input")
        report = await _verifier(engine, scope, budget, "redirect-authorized").verify(
            candidate, "hello"
        )
    finally:
        await engine.aclose()

    assert report.outcome == SQLiVerificationOutcome.INCONCLUSIVE
    assert report.request_count == 9
    assert all(sample.status_code == 302 for sample in report.samples)
    assert server.RequestHandlerClass.state["request_count"] == 9
    assert budget.used("redirect-authorized", candidate.target) == 9
    assert "outside.invalid" not in server.RequestHandlerClass.state["resolver_calls"]


@pytest.mark.parametrize(
    "parameters",
    [{"id": "1 OR 1"}, {"id OR 1": "1"}],
)
@pytest.mark.asyncio
async def test_orchestrator_rejects_unsafe_input_before_detection(
    local_target, tmp_path, monkeypatch, parameters
):
    base, scope, engine, server, _ = local_target
    monkeypatch.chdir(tmp_path)
    target = f"{base}/sqli/sqlite-vulnerable"
    scan_id = "phase5-invalid-orchestrator"
    budget = BudgetManager(100)
    orchestrator, pipeline = _orchestrator(base, target, scope, engine, budget, scan_id, tmp_path)
    reports = await orchestrator.assess_sqli(_detector(engine, scope, budget, scan_id), parameters)
    assessment = await orchestrator.finalize()
    await pipeline.close()

    assert reports[0].outcome == SQLiVerificationOutcome.NOT_TESTED
    assert reports[0].request_count == 0
    assert server.RequestHandlerClass.state["request_count"] == 0
    assert assessment.findings == [] and assessment.candidates == []


@pytest.mark.parametrize("finding_type", ["SQL_INJECTION", "SQL_INJECTION ", "SQL-INJECTION", "SQL INJECTION", "SQLi"])
@pytest.mark.asyncio
async def test_ordinary_result_submission_cannot_inject_sql_injection_finding(
    local_target, tmp_path, finding_type
):
    base, scope, engine, _, _ = local_target
    target = f"{base}/sqli/sqlite-vulnerable"
    budget = BudgetManager(100)
    orchestrator, pipeline = _orchestrator(base, target, scope, engine, budget, "gate", tmp_path)
    finding = Finding(
        type=finding_type, target=target, parameter="id", method="GET",
        severity=Severity.HIGH, confidence=0.9, source="UNTRUSTED",
    )
    with pytest.raises(ValueError, match="assess_sqli"):
        orchestrator.add_result(
            "UNTRUSTED", AdapterScanResult([finding], [], TestOutcome.PRESENT, "fabricated"),
            target=target,
        )
    await pipeline.close()


@pytest.mark.asyncio
async def test_candidate_identity_deduplicates_exact_repeats_without_aliasing_techniques(
    local_target, tmp_path
):
    base, scope, engine, _, _ = local_target
    target = f"{base}/sqli/candidate-only"
    orchestrator, pipeline = _orchestrator(
        base, target, scope, engine, BudgetManager(100), "candidate-identity", tmp_path,
        enable_ai=False,
    )
    error_candidate = _candidate(target, "id", "error_based")
    repeated_candidate = DetectionCandidate(
        finding_type="SQL_INJECTION", target=target, parameter="id", method="GET",
        technique="error_based", confidence=0.81, evidence=(),
        reason="second observation", verification_required="database behavior",
    )
    boolean_candidate = _candidate(target, "id", "boolean_based")
    orchestrator.add_result(
        "SQLI",
        AdapterScanResult(
            [], [error_candidate, repeated_candidate, boolean_candidate],
            TestOutcome.INCONCLUSIVE, "candidate observations", 0,
        ),
        target=target,
        test_family="SQLI",
    )
    assessment = await orchestrator.finalize()
    await pipeline.close()

    assert len(assessment.candidates) == 2
    assert {candidate.technique for candidate in assessment.candidates} == {
        "error_based", "boolean_based",
    }
    assert next(candidate for candidate in assessment.candidates
                if candidate.technique == "error_based").confidence == 0.81


@pytest.mark.asyncio
async def test_fixed_finding_requires_completed_not_confirmed_coverage(
    local_target, tmp_path, monkeypatch
):
    base, scope, engine, server, _ = local_target
    monkeypatch.chdir(tmp_path)
    target = f"{base}/sqli/sqlite-toggle"
    pipeline = FindingsPipeline(db_name=str(tmp_path / "lifecycle.sqlite"), enable_ai=False)

    scan1 = "phase5-lifecycle-1"
    budget1 = BudgetManager(100)
    context1 = create_context(
        project_id="phase5-project", scan_id=scan1,
        scan_date="2026-11-17T12:00:00Z", target_url=target,
        scope=scope, request_engine=engine, budget_manager=budget1,
    )
    orchestrator1 = AssessmentOrchestrator(context1, pipeline, Reporter())
    reports1 = await orchestrator1.assess_sqli(_detector(engine, scope, budget1, scan1), {"id": "1"})
    first = await orchestrator1.finalize()
    assert reports1[0].outcome == SQLiVerificationOutcome.VERIFIED
    assert first.findings[0].status == FindingStatus.OPEN

    server.RequestHandlerClass.state["sqli_mode"] = "incomplete"
    scan2 = "phase5-lifecycle-2"
    budget2 = BudgetManager(100)
    context2 = create_context(
        project_id="phase5-project", scan_id=scan2,
        scan_date="2026-11-18T12:00:00Z", target_url=target,
        scope=scope, request_engine=engine, budget_manager=budget2,
    )
    orchestrator2 = AssessmentOrchestrator(context2, pipeline, Reporter())
    reports2 = await orchestrator2.assess_sqli(_detector(engine, scope, budget2, scan2), {"id": "1"})
    second = await orchestrator2.finalize()

    assert reports2[0].outcome == SQLiVerificationOutcome.INCONCLUSIVE
    assert len(second.findings) == 1
    assert second.findings[0].observation_status == ObservationStatus.NOT_TESTED
    assert second.findings[0].status == FindingStatus.OPEN
    assert len(second.candidates) == 1

    server.RequestHandlerClass.state["sqli_mode"] = "normal"
    server.RequestHandlerClass.state["sqli_safe"] = True
    scan3 = "phase5-lifecycle-3"
    budget3 = BudgetManager(100)
    context3 = create_context(
        project_id="phase5-project", scan_id=scan3,
        scan_date="2026-11-19T12:00:00Z", target_url=target,
        scope=scope, request_engine=engine, budget_manager=budget3,
    )
    orchestrator3 = AssessmentOrchestrator(context3, pipeline, Reporter())
    reports3 = await orchestrator3.assess_sqli(_detector(engine, scope, budget3, scan3), {"id": "1"})
    third = await orchestrator3.finalize()
    persisted = await pipeline.db_manager.get_active_findings("phase5-project")
    await pipeline.close()

    assert reports3 == []
    assert len(third.findings) == 1
    assert third.findings[0].observation_status == ObservationStatus.ABSENT
    assert third.findings[0].status == FindingStatus.FIXED
    assert persisted[0].status == FindingStatus.FIXED

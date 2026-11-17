import asyncio
import json
import os
import threading

import pytest

from adapters.adapter2.request import RequestConfig, RequestEngine
from adapters.adapter2.scope import ScopeEngine
from adapters.adapter2.sqli import SQLiDetector
from adapters.adapter2.xss import XSSDetector
from adapters.adapter2.waf import WAFDetector
from adapters.adapter2.budget import BudgetManager
from adapters.adapter2.context import create_context
from adapters.adapter2.framework import TestRequest
from adapters.adapter2.orchestrator import AssessmentOrchestrator
from core_engine import FindingsPipeline
from reporting.reporter import Reporter
from tests.local_vulnerable_app import start_server


@pytest.fixture
async def local_target():
    server = start_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    scope = ScopeEngine(
        allowed_hosts={host}, allowed_schemes={"http"},
        allowed_ports={port}, allowed_path_prefixes=("/",),
        allowed_methods={"GET"},
    )

    async def resolver(name, requested_port):
        assert name == host and requested_port == port
        return [host]

    engine = RequestEngine(
        scope, config=RequestConfig(allow_private_ips=True), resolver=resolver,
    )
    try:
        yield f"http://{host}:{port}", scope, engine, server
    finally:
        await engine.aclose()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        try:
            os.unlink(server.db_path)
        except FileNotFoundError:
            pass


@pytest.mark.asyncio
async def test_sqli_distinguishes_real_sqlite_query_from_parameterized_control(local_target):
    base, scope, engine, _ = local_target
    detector = SQLiDetector(
        engine, scope, enable_time_based=False, enable_union_based=False,
    )
    vulnerable = await detector.scan(f"{base}/sqli/sqlite-vulnerable", {"id": "1"})
    assert vulnerable.findings == []
    assert len(vulnerable.candidates) == 1
    assert vulnerable.coverage_outcome.value == "INCONCLUSIVE"
    assert "sqlite3.OperationalError" in vulnerable.candidates[0].evidence[0].response_body_snippet

    safe = await detector.scan(f"{base}/sqli/sqlite-safe", {"id": "1"})
    assert safe.findings == []
    assert safe.candidates == []
    assert safe.coverage_outcome.value == "ABSENT"


@pytest.mark.asyncio
async def test_xss_reflection_is_candidate_and_escaped_output_is_absent(local_target):
    base, scope, engine, _ = local_target
    detector = XSSDetector(engine, scope, max_requests_per_target=100)
    vulnerable = await detector.scan(f"{base}/reflect", {"input": "hello"})
    assert vulnerable.findings == []
    assert vulnerable.candidates
    assert vulnerable.coverage_outcome.value == "INCONCLUSIVE"
    assert vulnerable.candidates[0].verification_required == "browser execution instrumentation"

    safe = await detector.scan(f"{base}/reflect-safe", {"input": "hello"})
    assert safe.findings == []
    assert safe.candidates == []
    assert safe.coverage_outcome.value == "ABSENT"

    csp = await detector.scan(f"{base}/csp-strict", {"input": "hello"})
    assert csp.candidates
    assert csp.candidates[0].evidence[0].contextual_analysis
    assert "CSP for" in csp.candidates[0].evidence[0].contextual_analysis


@pytest.mark.asyncio
async def test_security_adapters_share_request_engine_budget_and_concurrency(local_target):
    base, scope, engine, _ = local_target
    scan_id = "shared-adapter-execution"
    budget = BudgetManager(default_max_requests=10)
    adapters = [
        WAFDetector(engine, scope, budget_manager=budget, scan_id=scan_id),
        SQLiDetector(
            engine, scope, enable_time_based=False, enable_union_based=False,
            budget_manager=budget, scan_id=scan_id,
        ),
        XSSDetector(engine, scope, budget_manager=budget, scan_id=scan_id),
    ]

    outcomes = [
        await adapter.execute_request(TestRequest(f"{base}/reflect", params={"input": "hello"}))
        for adapter in adapters
    ]

    assert all(outcome.ok for outcome in outcomes)
    assert len({adapter.max_concurrent_requests for adapter in adapters}) == 1
    assert all(adapter.budget_manager is budget for adapter in adapters)
    assert budget.used(scan_id, base) == 3


@pytest.mark.asyncio
async def test_adapter_results_flow_through_coverage_core_and_candidate_report(local_target, tmp_path, monkeypatch):
    base, scope, engine, _ = local_target
    monkeypatch.chdir(tmp_path)
    scan_id = "phase4-orchestration"
    budget = BudgetManager(default_max_requests=100)

    waf_url = f"{base}/waf/observed"
    sql_url = f"{base}/sqli/sqlite-vulnerable"
    waf = WAFDetector(engine, scope, budget_manager=budget, scan_id=scan_id)
    sqli = SQLiDetector(
        engine, scope, enable_time_based=False, enable_union_based=False,
        budget_manager=budget, scan_id=scan_id,
    )
    waf_result = await waf.scan(waf_url)
    sql_result = await sqli.scan(sql_url, {"id": "1"})
    assert waf_result.findings
    assert sql_result.candidates

    context = create_context(
        project_id="phase4-project", scan_id=scan_id,
        scan_date="2026-11-17T12:00:00Z", target_url=base,
        scope=scope, request_engine=engine,
    )
    pipeline = FindingsPipeline(db_name=str(tmp_path / "core.sqlite"), enable_ai=True)
    ai_eligible = []
    async def record_ai_eligibility(finding):
        ai_eligible.append(finding.type)
        return finding
    pipeline.analyze_with_limit = record_ai_eligibility
    orchestrator = AssessmentOrchestrator(context, pipeline, Reporter())
    orchestrator.add_result("WAF", waf_result, target=waf_url, test_family="WAF")
    # Duplicate adapter output must not duplicate Core lifecycle or candidate entries.
    orchestrator.add_result("WAF", waf_result, target=waf_url, test_family="WAF")
    orchestrator.add_result("SQLI", sql_result, target=sql_url, finding_type="SQL_INJECTION",
                            parameter="id", test_family="SQLI")
    orchestrator.add_result("SQLI", sql_result, target=sql_url, finding_type="SQL_INJECTION",
                            parameter="id", test_family="SQLI")
    report_path = tmp_path / "assessment.json"
    assessment = await orchestrator.finalize(str(report_path))
    persisted = await pipeline.db_manager.get_active_findings("phase4-project")
    await pipeline.close()

    assert len(assessment.findings) == 1
    assert len(persisted) == 1
    assert len(assessment.candidates) == 1
    assert assessment.coverage_outcome.value == "PRESENT"
    assert {record.outcome.value for record in assessment.coverage_records} == {"PRESENT", "INCONCLUSIVE"}
    assert ai_eligible == ["WAF_DETECTED"]
    rendered = json.loads(report_path.read_text(encoding="utf-8"))
    assert len(rendered["findings"]) == 1
    assert len(rendered["candidates"]) == 1
    assert rendered["candidates"][0]["evidence"]
    assert rendered["candidates"][0]["verification_required"] == "verified vulnerable database behavior"
    assert {record["outcome"] for record in rendered["coverage_records"]} == {
        "PRESENT", "INCONCLUSIVE",
    }

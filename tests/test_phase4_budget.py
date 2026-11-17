import asyncio

import pytest

from adapters.adapter2.budget import (
    BudgetExhaustedError,
    BudgetManager,
    InvalidBudgetOriginError,
    target_origin,
)
from adapters.adapter2.framework import (
    AttemptStatus,
    BaseVulnerabilityAdapter,
    TestRequest,
)
from adapters.adapter2.models import TestOutcome


def test_target_origin_ignores_path_query_fragment_and_rejects_userinfo():
    origin = target_origin("https://example.com/a?b=1#frag")
    assert origin == "https://example.com:443"
    with pytest.raises(InvalidBudgetOriginError):
        target_origin("https://user:pass@example.com/other")
    assert target_origin("http://example.com:80/x") == "http://example.com:80"


def test_target_origin_rejects_invalid_origins_and_formats_ipv6():
    with pytest.raises(InvalidBudgetOriginError):
        target_origin("https://example.com:99999/x")
    with pytest.raises(InvalidBudgetOriginError):
        target_origin("http:///path")
    assert target_origin("http://[::1]/x") == "http://[::1]:80"
    assert target_origin("https://[2001:db8::1]:8080/x") == (
        "https://[2001:db8::1]:8080"
    )
    for invalid in (
        "example.com/path", "ftp://example.com", "http://example.com:0",
        "http://example.com:65536", "http://bad_host.test", "http:///path",
        "http://user@example.com/", "http://[broken/",
    ):
        with pytest.raises(InvalidBudgetOriginError):
            target_origin(invalid)


@pytest.mark.asyncio
async def test_budget_is_atomic_under_concurrency():
    manager = BudgetManager(default_max_requests_per_target=10)

    async def reserve_one():
        try:
            await asyncio.to_thread(manager.reserve, "scan-1", "https://example.com/x")
            return True
        except BudgetExhaustedError:
            return False

    results = await asyncio.gather(*(reserve_one() for _ in range(50)))
    assert sum(results) == 10
    assert manager.used("scan-1", "https://example.com") == 10


@pytest.mark.asyncio
async def test_reset_scan_clears_usage_and_limits():
    manager = BudgetManager(default_max_requests_per_target=2)
    manager.set_limit("scan-1", "https://example.com", 1)
    manager.reserve("scan-1", "https://example.com/a")
    manager.reset_scan("scan-1")
    assert manager.used("scan-1", "https://example.com") == 0
    assert manager.limit("scan-1", "https://example.com") == 2


@pytest.mark.asyncio
async def test_invalid_amounts_and_boolean_limits_are_rejected():
    manager = BudgetManager()
    for amount in (0, -1, True, 1.5, "1"):
        with pytest.raises(ValueError):
            manager.reserve("scan-1", "https://example.com", amount=amount)
    with pytest.raises(ValueError):
        manager.set_limit("scan-1", "https://example.com", True)
    with pytest.raises(InvalidBudgetOriginError):
        manager.used("scan-1", "missing-scheme.example")


@pytest.mark.asyncio
async def test_missing_engine_is_rejected_before_budget_reservation():
    manager = BudgetManager(default_max_requests_per_target=10)
    adapter = BaseVulnerabilityAdapter(
        request_engine=None,
        scope_engine=type("Scope", (), {
            "is_authorized": lambda self, url, method="GET": True
        })(),
        budget_manager=manager,
        scan_id="scan-1",
    )
    outcome = await adapter.execute_request(
        TestRequest(url="https://example.com/")
    )
    assert outcome.status == AttemptStatus.TRANSPORT_ERROR
    assert outcome.coverage_outcome == TestOutcome.ERROR
    assert manager.used("scan-1", "https://example.com/") == 0


@pytest.mark.asyncio
async def test_scope_rejection_does_not_consume_budget_or_call_engine():
    from unittest.mock import AsyncMock

    manager = BudgetManager(default_max_requests=10)
    engine = type("Engine", (), {"send_request": AsyncMock()})()
    scope = type("Scope", (), {"is_authorized": lambda self, url, method="GET": False})()
    adapter = BaseVulnerabilityAdapter(
        engine, scope, budget_manager=manager, scan_id="scan-scope",
    )

    outcome = await adapter.execute_request(TestRequest("https://example.com/"))

    assert outcome.status == AttemptStatus.SCOPE_REJECTED
    assert manager.used("scan-scope", "https://example.com/") == 0
    engine.send_request.assert_not_awaited()


@pytest.mark.asyncio
async def test_invalid_origin_fails_closed_before_engine_call():
    from unittest.mock import AsyncMock

    manager = BudgetManager(default_max_requests=10)
    engine = type("Engine", (), {"send_request": AsyncMock()})()
    scope = type("Scope", (), {"is_authorized": lambda self, url, method="GET": True})()
    adapter = BaseVulnerabilityAdapter(
        engine, scope, budget_manager=manager, scan_id="scan-invalid-origin",
    )

    outcome = await adapter.execute_request(TestRequest("not a valid URL"))

    assert outcome.status == AttemptStatus.TRANSPORT_ERROR
    assert outcome.error_category == "invalid_origin"
    assert manager.stats("scan-invalid-origin") == {}
    engine.send_request.assert_not_awaited()


@pytest.mark.asyncio
async def test_adapters_share_origin_budgets_but_not_other_origins():
    from unittest.mock import AsyncMock
    from adapters.adapter2.request import RequestResult

    manager = BudgetManager(default_max_requests=10)
    scope = type("Scope", (), {"is_authorized": lambda self, url, method="GET": True})()

    def make_engine():
        engine = type("Engine", (), {})()
        async def send_request(method, url, **kwargs):
            return RequestResult(True, url, status_code=200, text="ok", elapsed_ms=1)
        engine.send_request = AsyncMock(side_effect=send_request)
        return engine

    first = BaseVulnerabilityAdapter(make_engine(), scope, budget_manager=manager, scan_id="shared")
    second = BaseVulnerabilityAdapter(make_engine(), scope, budget_manager=manager, scan_id="shared")
    other_origin = BaseVulnerabilityAdapter(make_engine(), scope, budget_manager=manager, scan_id="shared")
    assert (await first.execute_request(TestRequest("https://one.test/a"))).ok
    assert (await second.execute_request(TestRequest("https://one.test/b"))).ok
    assert (await other_origin.execute_request(TestRequest("https://two.test/a"))).ok
    assert manager.used("shared", "https://one.test") == 2
    assert manager.used("shared", "https://two.test") == 1

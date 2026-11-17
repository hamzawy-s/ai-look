from adapters.adapter2.models import TestOutcome
from tests.helpers import FakeEngine, FakeScope, StubAdapter, ctx, step


async def test_default_scope_is_present_and_authorizes_default_target():
    context = ctx()
    assert context.scope_engine is not None
    adapter = StubAdapter(context, [step(TestOutcome.PRESENT)])
    assert adapter.is_authorized(context.target_url) is True


async def test_explicit_none_is_preserved():
    context = ctx(scope=None)
    assert context.scope_engine is None


async def test_missing_scope_fails_closed():
    context = ctx(scope=None)
    adapter = StubAdapter(context, [step(TestOutcome.PRESENT)])
    assert adapter.is_authorized(context.target_url) is False


async def test_unauthorized_scope_fails_closed():
    context = ctx(scope=FakeScope(allowed=False))
    adapter = StubAdapter(context, [step(TestOutcome.PRESENT)])
    assert adapter.is_authorized(context.target_url) is False


async def test_scope_exception_fails_closed():
    class BoomScope:
        def is_authorized(self, url: str, method: str = "GET") -> bool:
            raise RuntimeError("boom")

    context = ctx(scope=BoomScope())
    adapter = StubAdapter(context, [])
    assert adapter.is_authorized(context.target_url) is False


async def test_zero_network_calls_when_scope_missing():
    engine = FakeEngine()
    context = ctx(scope=None, engine=engine)
    adapter = StubAdapter(context, [step(TestOutcome.PRESENT)])
    await adapter.execute()
    assert engine.calls == []
    assert adapter.findings == []
    assert context.coverage.records() == []


async def test_zero_network_calls_when_unauthorized():
    engine = FakeEngine()
    context = ctx(scope=FakeScope(allowed=False), engine=engine)
    adapter = StubAdapter(context, [step(TestOutcome.PRESENT)])
    await adapter.execute()
    assert engine.calls == []
    assert adapter.findings == []
    assert context.coverage.records() == []


async def test_authorized_execution_makes_one_fake_request_and_produces_results():
    engine = FakeEngine()
    context = ctx(engine=engine)
    adapter = StubAdapter(context, [step(TestOutcome.PRESENT)])
    await adapter.execute()
    assert len(engine.calls) == 1
    assert len(adapter.findings) == 1
    assert len(context.coverage.records()) == 1
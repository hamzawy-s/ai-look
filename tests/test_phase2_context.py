from adapters.adapter2.context import create_context
from adapters.adapter2.models import TestOutcome
from adapters.adapter2.scope import ScopeEngine
from tests.helpers import FakeEngine, FakeScope, StubAdapter, step


def base_kwargs(**overrides):
    kwargs = dict(
        project_id="p1",
        scan_id="s1",
        scan_date="2026-01-01T00:00:00Z",
        target_url="https://t.local/api/users",
    )
    kwargs.update(overrides)
    return kwargs


def test_omitted_scope_without_config_is_deny_all_not_none():
    context = create_context(**base_kwargs())
    assert isinstance(context.scope_engine, ScopeEngine)
    assert context.scope_engine is not None
    assert context.scope_engine.is_authorized(context.target_url) is False


def test_explicit_none_is_preserved():
    context = create_context(**base_kwargs(scope=None))
    assert context.scope_engine is None


def test_omitted_scope_with_config_authorizes():
    context = create_context(
        **base_kwargs(
            scope_config={"allowed_hosts": {"t.local"}, "allowed_schemes": {"https"}}
        )
    )
    assert context.scope_engine.is_authorized(context.target_url) is True


def test_explicit_scope_overrides_config():
    explicit = FakeScope(allowed=False)
    context = create_context(
        **base_kwargs(scope=explicit, scope_config={"allowed_hosts": {"t.local"}})
    )
    assert context.scope_engine is explicit
    assert context.scope_engine.is_authorized(context.target_url) is False


async def test_no_request_when_authorization_fails_deny_all():
    engine = FakeEngine()
    context = create_context(**base_kwargs(request_engine=engine))
    adapter = StubAdapter(context, [step(TestOutcome.PRESENT)])
    await adapter.execute()
    assert engine.calls == []
    assert adapter.findings == []
    assert context.coverage.records() == []


async def test_no_request_when_scope_is_none():
    engine = FakeEngine()
    context = create_context(**base_kwargs(scope=None, request_engine=engine))
    adapter = StubAdapter(context, [step(TestOutcome.PRESENT)])
    await adapter.execute()
    assert engine.calls == []
    assert adapter.findings == []
    assert context.coverage.records() == []


async def test_authorized_context_makes_one_fake_request():
    engine = FakeEngine()
    context = create_context(
        **base_kwargs(
            scope_config={"allowed_hosts": {"t.local"}, "allowed_schemes": {"https"}},
            request_engine=engine,
        )
    )
    adapter = StubAdapter(context, [step(TestOutcome.PRESENT)])
    await adapter.execute()
    assert len(engine.calls) == 1
    assert len(adapter.findings) == 1
    assert len(context.coverage.records()) == 1
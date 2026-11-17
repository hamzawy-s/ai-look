from core_engine import ObservationStatus, Severity

from adapters.adapter2.models import TestOutcome
from tests.helpers import StubAdapter, ctx, step


def test_step_emits_type_key():
    item = step(TestOutcome.PRESENT)
    assert "type" in item
    assert "typ" not in item
    assert item["type"] == "SQL_INJECTION"


async def test_one_present_step_produces_one_finding_and_one_coverage():
    context = ctx()
    adapter = StubAdapter(context, [step(TestOutcome.PRESENT)])
    await adapter.execute()

    assert len(adapter.findings) == 1
    finding = adapter.findings[0]
    assert finding.observation_status == ObservationStatus.PRESENT
    assert finding.type == "SQL_INJECTION"
    assert finding.target == "/api/users"
    assert finding.parameter == "id"
    assert finding.method == "GET"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 0.9
    assert finding.source == "STUB"
    assert finding.evidence == ["stub"]

    records = context.coverage.records()
    assert len(records) == 1
    record = records[0]
    assert record.outcome == TestOutcome.PRESENT
    assert record.fingerprint == finding.fingerprint
    assert record.finding_type == finding.type
    assert record.target == finding.target
    assert record.parameter == finding.parameter
    assert record.method == finding.method


async def test_absent_step_records_coverage_without_finding():
    context = ctx()
    adapter = StubAdapter(context, [step(TestOutcome.ABSENT)])
    await adapter.execute()

    assert adapter.findings == []
    records = context.coverage.records()
    assert len(records) == 1
    assert records[0].outcome == TestOutcome.ABSENT
    assert context.coverage.tested_fingerprints() == {records[0].fingerprint}


async def test_blocked_outcome_is_not_executed_coverage():
    context = ctx()
    adapter = StubAdapter(context, [step(TestOutcome.BLOCKED)])
    await adapter.execute()
    assert adapter.findings == []
    assert len(context.coverage.records()) == 1
    assert context.coverage.tested_fingerprints() == set()


async def test_error_outcome_is_not_executed_coverage():
    context = ctx()
    adapter = StubAdapter(context, [step(TestOutcome.ERROR)])
    await adapter.execute()
    assert adapter.findings == []
    assert len(context.coverage.records()) == 1
    assert context.coverage.tested_fingerprints() == set()


async def test_skipped_outcome_is_not_executed_coverage():
    context = ctx()
    adapter = StubAdapter(context, [step(TestOutcome.SKIPPED)])
    await adapter.execute()
    assert adapter.findings == []
    assert len(context.coverage.records()) == 1
    assert context.coverage.tested_fingerprints() == set()


async def test_inconclusive_outcome_is_not_executed_coverage():
    context = ctx()
    adapter = StubAdapter(context, [step(TestOutcome.INCONCLUSIVE)])
    await adapter.execute()
    assert adapter.findings == []
    assert len(context.coverage.records()) == 1
    assert context.coverage.tested_fingerprints() == set()


async def test_duplicate_steps_dedup_coverage_and_present_wins():
    context = ctx()
    adapter = StubAdapter(
        context,
        [step(TestOutcome.ABSENT), step(TestOutcome.PRESENT)],
    )
    await adapter.execute()

    assert len(adapter.findings) == 1
    records = context.coverage.records()
    assert len(records) == 1
    assert records[0].outcome == TestOutcome.PRESENT
    assert len(context.coverage.tested_fingerprints()) == 1
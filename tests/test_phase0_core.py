import hashlib
import pytest
from core_engine import (FindingsPipeline, Finding, Severity, FindingStatus,
                         ObservationStatus, DeduplicationEngine)

def mk(param, target="/api/users", typ="SQL_INJECTION", source="A1"):
    return Finding(type=typ, target=target, method="GET", parameter=param,
                   severity=Severity.HIGH, confidence=0.9, source=source)

def fp(param):
    return DeduplicationEngine().fingerprint_for("GET", "/api/users", "SQL_INJECTION", param)

@pytest.fixture
async def pipeline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = FindingsPipeline(db_name=":memory:", enable_ai=False)
    await p.db_manager.connect()
    yield p
    await p.close()

async def test_fingerprint_backward_compatible():
    d = DeduplicationEngine()
    f = Finding(type="SQL_Injection", target="/api/users/", parameter="id", method="get",
                severity=Severity.HIGH, confidence=0.9, source="X")
    old = hashlib.sha256(b"GET|/api/users|SQL_INJECTION|id").hexdigest()
    assert d.generate_fingerprint(f) == old
    assert d.fingerprint_for("get", "/api/users/", "SQL_Injection", "id") == old

async def test_lifecycle_unchanged(pipeline):
    fa = fp("id")
    await pipeline.process("p1","s1","2026-09-01T10:00:00Z",{fa},[mk("id")])
    f1 = (await pipeline.db_manager.get_active_findings("p1"))[0]
    assert f1.status == FindingStatus.OPEN
    await pipeline.process("p1","s2","2026-09-02T10:00:00Z",{fa},[])
    assert (await pipeline.db_manager.get_active_findings("p1"))[0].status == FindingStatus.FIXED
    await pipeline.process("p1","s3","2026-09-03T10:00:00Z",set(),[])
    assert (await pipeline.db_manager.get_active_findings("p1"))[0].status == FindingStatus.FIXED
    await pipeline.process("p1","s4","2026-09-04T10:00:00Z",{fa},[mk("id")])
    f4 = (await pipeline.db_manager.get_active_findings("p1"))[0]
    assert f4.status == FindingStatus.REOPENED and f4.id == f1.id

async def test_observation_status_roundtrip(pipeline):
    fa = fp("id")
    await pipeline.process("p1","s1","2026-09-01T10:00:00Z",{fa},[mk("id")])
    await pipeline.process("p1","s2","2026-09-02T10:00:00Z",{fa},[])
    assert (await pipeline.db_manager.get_active_findings("p1"))[0].observation_status == ObservationStatus.ABSENT
    await pipeline.process("p1","s3","2026-09-03T10:00:00Z",set(),[])
    assert (await pipeline.db_manager.get_active_findings("p1"))[0].observation_status == ObservationStatus.NOT_TESTED

async def test_ai_only_for_present_and_no_finding_loss(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = FindingsPipeline(db_name=":memory:", enable_ai=True)
    await p.db_manager.connect()
    calls = []
    class RecordingAI:
        async def generate_remediation(self, finding):
            calls.append(finding.parameter); return finding
        async def close(self): pass
    p.ai_layer = RecordingAI()
    a,b,c = fp("a"), fp("b"), fp("c")
    await p.process("p1","s1","2026-09-01T10:00:00Z",{a,b,c},[mk("a"),mk("b"),mk("c")])
    calls.clear()
    await p.process("p1","s2","2026-09-02T10:00:00Z",{a,b},[mk("a")])
    assert calls == ["a"]
    findings = await p.db_manager.get_active_findings("p1")
    assert len(findings) == 3
    by = {f.parameter: f for f in findings}
    assert by["a"].observation_status == ObservationStatus.PRESENT
    assert by["b"].observation_status == ObservationStatus.ABSENT
    assert by["c"].observation_status == ObservationStatus.NOT_TESTED
    await p.close()
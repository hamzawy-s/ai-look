from adapters.adapter2.framework import Evidence
from adapters.adapter2.sqli import DBMSType, InjectionTechnique, SQLiDetectionResult, SQLiDetector
from core_engine import Finding


def test_unverified_sql_error_candidate_never_becomes_core_finding():
    detector = SQLiDetector(None, None)
    detection = SQLiDetectionResult(
        InjectionTechnique.ERROR_BASED, DBMSType.SQLITE, 0.8, "'",
        [Evidence(
            "http://127.0.0.1:8000/test?id=%27", "GET", {}, None, 500, {},
            "sqlite3.OperationalError: syntax error", "SQLite database error", 5,
        )],
    )
    candidate = detector._create_sqli_candidate(
        "http://127.0.0.1:8000/test", "id", detection, "error_based"
    )
    assert candidate.finding_type == "SQL_INJECTION"
    assert candidate.technique == "error_based"
    assert candidate.verification_required == "verified vulnerable database behavior"
    assert candidate.confidence == 0.8
    assert not isinstance(candidate, Finding)

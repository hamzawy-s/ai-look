"""Tests for the SQL injection detection adapter."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from adapters.adapter2.framework import Evidence, TestResponse
from adapters.adapter2.signatures import Signature
from adapters.adapter2.sqli import (
    DBMSType,
    InjectionTechnique,
    SQLiDetectionResult,
    SQLiDetector,
)
from core_engine import Severity


@pytest.fixture
def request_engine():
    engine = MagicMock()
    engine.send_request = AsyncMock()
    return engine


@pytest.fixture
def scope_engine():
    scope = MagicMock()
    scope.is_authorized.return_value = True
    return scope


@pytest.fixture
def detector(request_engine, scope_engine):
    return SQLiDetector(request_engine, scope_engine, max_requests_per_target=100)


def response(body, status_code=200, elapsed_ms=100):
    return TestResponse(status_code, {}, body, elapsed_ms)


def test_dbms_identification(detector):
    assert detector._identify_dbms("SQL syntax near MySQL") == DBMSType.MYSQL
    assert detector._identify_dbms("PostgreSQL query failed") == DBMSType.POSTGRESQL
    assert detector._identify_dbms("Unclosed quotation mark") == DBMSType.SQLSERVER
    assert detector._identify_dbms("ordinary response") == DBMSType.UNKNOWN


def test_detection_result_threshold():
    result = SQLiDetectionResult(
        InjectionTechnique.ERROR_BASED, DBMSType.MYSQL, 0.5, "'", []
    )
    assert result.is_vulnerable


def test_confidence_calculations(detector):
    matches = [
        Signature("mysql", "MySQL", severity_hint="HIGH"),
        Signature("syntax", "Syntax"),
    ]
    assert detector._calculate_error_based_confidence(
        matches, response("normal"), response("SQL syntax MySQL", 500)
    ) >= 0.5
    assert detector._calculate_time_based_confidence(2000, 100) == 0.0
    assert detector._calculate_time_based_confidence(5500, 5000) == 0.0
    assert detector._calculate_boolean_based_confidence(
        response("user"), response("admin"), response("user")
    ) >= 0.5


@pytest.mark.asyncio
async def test_error_based_detection(detector, request_engine):
    request_engine.send_request.return_value = MagicMock(
        ok=True,
        status_code=500,
        headers={},
        text="SQL syntax error near MySQL",
        elapsed_ms=100,
    )
    result = await detector.detect_error_based(
        "https://example.com/api", "id", "1", response("normal")
    )
    assert result is not None
    assert result.dbms_type == DBMSType.MYSQL
    assert result.technique == InjectionTechnique.ERROR_BASED


@pytest.mark.asyncio
async def test_time_based_detection(detector, request_engine):
    request_engine.send_request.side_effect = [
        MagicMock(ok=True, status_code=200, headers={}, text="control", elapsed_ms=100),
        MagicMock(ok=True, status_code=200, headers={}, text="delayed", elapsed_ms=5500),
        MagicMock(ok=True, status_code=200, headers={}, text="control", elapsed_ms=110),
        MagicMock(ok=True, status_code=200, headers={}, text="delayed", elapsed_ms=5600),
        MagicMock(ok=True, status_code=200, headers={}, text="control", elapsed_ms=90),
        MagicMock(ok=True, status_code=200, headers={}, text="delayed", elapsed_ms=5400),
    ]
    result = await detector.detect_time_based(
        "https://example.com/api", "id", "7", 100, DBMSType.MYSQL
    )
    assert result is not None
    assert result.time_delta_ms > 4000
    assert result.payload_used == "7 AND SLEEP(5)"
    assert len(result.evidence_list) == 3


@pytest.mark.asyncio
async def test_time_based_rejects_unstable_controls_and_timeout(detector, request_engine):
    request_engine.send_request.side_effect = [
        MagicMock(ok=True, status_code=200, headers={}, text="control", elapsed_ms=100),
        MagicMock(ok=True, status_code=200, headers={}, text="delay", elapsed_ms=5500),
        MagicMock(ok=True, status_code=200, headers={}, text="control", elapsed_ms=3000),
        MagicMock(ok=True, status_code=200, headers={}, text="delay", elapsed_ms=5600),
        MagicMock(ok=True, status_code=200, headers={}, text="control", elapsed_ms=110),
        MagicMock(ok=True, status_code=200, headers={}, text="delay", elapsed_ms=5400),
    ]
    unstable = await detector.detect_time_based("https://example.com/api", "id", "4", 100, DBMSType.MYSQL)
    assert unstable is None

    request_engine.send_request.side_effect = [
        MagicMock(ok=True, status_code=200, headers={}, text="control", elapsed_ms=100),
        MagicMock(ok=False, status_code=None, headers={}, text="", elapsed_ms=7000,
                  completed_exchange=False, error_category="timeout", error_message="timeout"),
    ]
    timeout_only = await detector.detect_time_based("https://example.com/api", "id", "4", 100, DBMSType.MYSQL)
    assert timeout_only is None


@pytest.mark.asyncio
async def test_boolean_based_detection(detector, request_engine):
    request_engine.send_request.side_effect = [
        MagicMock(ok=True, status_code=200, headers={}, text="user", elapsed_ms=100),
        MagicMock(ok=True, status_code=200, headers={}, text="user", elapsed_ms=100),
        MagicMock(ok=True, status_code=200, headers={}, text="admin", elapsed_ms=100),
        MagicMock(ok=True, status_code=200, headers={}, text="user", elapsed_ms=100),
        MagicMock(ok=True, status_code=200, headers={}, text="admin", elapsed_ms=100),
        MagicMock(ok=True, status_code=200, headers={}, text="user", elapsed_ms=100),
        MagicMock(ok=True, status_code=200, headers={}, text="admin", elapsed_ms=100),
        MagicMock(ok=True, status_code=200, headers={}, text="user", elapsed_ms=100),
    ]
    result = await detector.detect_boolean_based(
        "https://example.com/api", "id", "1", response("user")
    )
    assert result is not None
    assert result.technique == InjectionTechnique.BOOLEAN_BASED


def test_create_finding(detector):
    result = SQLiDetectionResult(
        InjectionTechnique.ERROR_BASED,
        DBMSType.MYSQL,
        0.9,
        "' OR 1=1--",
        [Evidence(
            "https://example.com/api", "GET", {}, None, 500, {},
            "SQL syntax error", "MySQL syntax error", 100
        )],
    )
    finding = detector._create_sqli_candidate(
        "https://example.com/api", "id", result, "error_based"
    )
    assert finding.finding_type == "SQL_INJECTION"
    assert finding.confidence == 0.9


@pytest.mark.asyncio
async def test_scope_and_budget_are_enforced(detector, scope_engine):
    scope_engine.is_authorized.return_value = False
    skipped = await detector.scan("https://unauthorized.example/api")
    assert skipped.findings == [] and skipped.candidates == []
    assert skipped.coverage_outcome.value == "SKIPPED"
    scope_engine.is_authorized.return_value = True
    detector.budget_manager.set_limit(detector.scan_id, "https://example.com/api", 1)
    detector.budget_manager.reserve(detector.scan_id, "https://example.com/api", 1)
    result = await detector.scan_parameter("https://example.com/api", "id", "1")
    assert result.candidates == []
    assert result.coverage_outcome.value == "SKIPPED"

"""Tests for the XSS detection adapter."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from adapters.adapter2.framework import Evidence, TestResponse
from adapters.adapter2.xss import (
    CspAnalyzer,
    XSSContext,
    XSSDetectionResult,
    XSSEncoding,
    XSSDetector,
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
    return XSSDetector(request_engine, scope_engine)


def response(body, status_code=200):
    return TestResponse(status_code, {}, body, 100)


def test_result_threshold():
    result = XSSDetectionResult(
        XSSContext.HTML_BODY, XSSEncoding.NONE, 0.8,
        "<script>alert(1)</script>", "html_body", []
    )
    assert result.is_vulnerable


def test_encoding_and_reflection_helpers(detector):
    assert detector._apply_encoding("<script>", XSSEncoding.NONE) == "<script>"
    assert "%3C" in detector._apply_encoding("<script>", XSSEncoding.URL)
    assert "&#x3c;" in detector._apply_encoding("<>", XSSEncoding.HTML_ENTITY)

    exact = detector._check_reflection(
        "<script>alert(1)</script>",
        "<script>alert(1)</script>",
        "Welcome <script>alert(1)</script>",
    )
    assert exact["reflected"] and exact["exact_match"]
    encoded = detector._check_reflection(
        "<script>", "%3Cscript%3E", "Welcome %3Cscript%3E"
    )
    assert encoded["reflected"] and encoded["encoded_match"]


def test_reflection_context_and_dangerous_payload(detector):
    assert detector._get_reflection_context(
        "alert(1)", "<script>var x = 'alert(1)';</script>"
    ) == "script_tag"
    assert detector._is_dangerous_reflection(
        "<img src=x onerror=alert(1)>", "html_body", ""
    )
    assert not detector._is_dangerous_reflection("hello", "html_body", "")


def test_confidence_reduced_for_waf_block(detector):
    reflection = {
        "reflected": True,
        "exact_match": True,
        "encoded_match": False,
        "reflection_context": "html_body",
    }
    assert detector._calculate_xss_confidence(
        "<script>alert(1)</script>", reflection, response("Blocked", 403)
    ) < 0.5


def test_csp_context_directives_nonce_and_fallbacks():
    analyzer = CspAnalyzer()
    headers = {"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline' 'nonce-abcd'; script-src-attr 'unsafe-inline'; script-src-elem 'self'"}
    assert analyzer.analyze(headers, XSSContext.HTML_ATTRIBUTE).allows_inline
    assert not analyzer.analyze(headers, XSSContext.HTML_BODY).allows_inline
    assert not analyzer.analyze(headers, XSSContext.JAVASCRIPT_CODE).allows_inline
    assert not analyzer.analyze({"Content-Security-Policy": "default-src 'self'"}).allows_inline
    assert analyzer.analyze({"Content-Security-Policy": "img-src 'self'"}).allows_inline


@pytest.mark.asyncio
async def test_reflected_xss_detection(detector, request_engine):
    request_engine.send_request.return_value = MagicMock(
        ok=True, status_code=200, headers={},
        text="Welcome <script>alert(1)</script> user",
        elapsed_ms=100, truncated=False, body_is_decoded=True,
        completed_exchange=True, error_category=None, url="https://example.com/search",
    )
    result = await detector.detect_reflected_xss(
        "https://example.com/search", "q", response("Welcome test_baseline")
    )
    assert result is not None
    assert result.context == XSSContext.HTML_BODY
    assert result.confidence >= 0.5


@pytest.mark.asyncio
async def test_dom_xss_detection(detector, request_engine):
    request_engine.send_request.return_value = MagicMock(
        ok=True, status_code=200, headers={},
        text="<script>document.write(location.hash);</script>",
        elapsed_ms=100, truncated=False, body_is_decoded=True,
        completed_exchange=True, error_category=None, url="https://example.com/page",
    )
    result = await detector.detect_dom_xss("https://example.com/page", "fragment")
    assert result is not None
    assert result.context == XSSContext.JAVASCRIPT_CODE


def test_create_finding(detector):
    result = XSSDetectionResult(
        XSSContext.HTML_BODY, XSSEncoding.NONE, 0.9,
        "<script>alert(1)</script>", "html_body",
        [Evidence(
            "https://example.com/search", "GET", {}, None, 200, {},
            "<script>alert(1)</script>", "XSS reflected", 100
        )],
    )
    finding = detector._create_xss_candidate(
        "https://example.com/search", "q", result
    )
    assert finding.finding_type == "XSS"
    assert finding.confidence == 0.9


@pytest.mark.asyncio
async def test_scope_and_budget_enforcement(detector, scope_engine):
    scope_engine.is_authorized.return_value = False
    skipped = await detector.scan("https://unauthorized.example/search")
    assert skipped.findings == [] and skipped.candidates == []
    assert skipped.coverage_outcome.value == "SKIPPED"
    scope_engine.is_authorized.return_value = True
    detector.budget_manager.set_limit(detector.scan_id, "https://example.com/search", 1)
    detector.budget_manager.reserve(detector.scan_id, "https://example.com/search", 1)
    result = await detector.scan_parameter("https://example.com/search", "q")
    assert result.candidates == []
    assert result.coverage_outcome.value == "SKIPPED"

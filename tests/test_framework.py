# tests/test_framework.py
"""Tests for vulnerability detection framework."""
import pytest
from adapters.adapter2.framework import (
    Payload, PayloadType, TestRequest, TestResponse,
    Evidence, BaseVulnerabilityAdapter
)
from adapters.adapter2.budget import BudgetManager, BudgetExhaustedError
from adapters.adapter2.signatures import Signature, SignatureMatcher


class TestPayload:
    def test_payload_creation(self):
        p = Payload(
            value="test",
            payload_type=PayloadType.ERROR_BASED,
            description="Test payload"
        )
        assert p.value == "test"
        assert p.payload_type == PayloadType.ERROR_BASED

    def test_payload_empty_value_rejected(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            Payload(value="", payload_type=PayloadType.BENIGN)


class TestTestRequest:
    def test_fingerprint_generation(self):
        req1 = TestRequest(url="http://test.com", method="GET", params={"id": "1"})
        req2 = TestRequest(url="http://test.com", method="GET", params={"id": "2"})
        req3 = TestRequest(url="http://test.com", method="GET", params={"id": "1"})

        assert req1.fingerprint != req2.fingerprint
        assert req1.fingerprint == req3.fingerprint

    def test_fingerprint_includes_method(self):
        get_req = TestRequest(url="http://test.com", method="GET")
        post_req = TestRequest(url="http://test.com", method="POST")
        assert get_req.fingerprint != post_req.fingerprint


class TestTestResponse:
    def test_is_error(self):
        ok_resp = TestResponse(status_code=200, headers={}, body="ok", elapsed_ms=100)
        err_resp = TestResponse(status_code=500, headers={}, body="error", elapsed_ms=100)

        assert not ok_resp.is_error
        assert err_resp.is_error

    def test_is_timeout(self):
        payload = Payload(
            value="test",
            payload_type=PayloadType.TIME_BASED,
            timeout_seconds=5.0
        )

        fast_resp = TestResponse(
            status_code=200, headers={}, body="", elapsed_ms=1000,
            payload=payload
        )
        slow_resp = TestResponse(
            status_code=200, headers={}, body="", elapsed_ms=6000,
            payload=payload
        )

        assert not fast_resp.is_timeout
        assert slow_resp.is_timeout


class TestEvidence:
    def test_evidence_creation(self):
        req = TestRequest(
            url="http://test.com/api",
            method="GET",
            headers={"User-Agent": "test"},
            params={"id": "1"},
        )
        resp = TestResponse(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="response body here",
            elapsed_ms=150,
        )

        evidence = Evidence.from_request_response(req, resp, "test-signature")

        assert evidence.request_url == "http://test.com/api?id=1"
        assert evidence.response_status == 200
        assert evidence.matched_signature == "test-signature"
        assert evidence.elapsed_ms == 150

    def test_evidence_sanitizes_credentials(self):
        req = TestRequest(url="http://test.com", method="GET")
        resp = TestResponse(
            status_code=200,
            headers={
                "Authorization": "Bearer secret123",
                "Cookie": "session=abc",
                "Content-Type": "text/html",
            },
            body="ok",
            elapsed_ms=100,
        )

        evidence = Evidence.from_request_response(req, resp, "sig")

        assert evidence.response_headers["Authorization"] == "[REDACTED]"
        assert evidence.response_headers["Cookie"] == "[REDACTED]"
        assert "Content-Type" in evidence.response_headers

    def test_evidence_truncates_long_body(self):
        req = TestRequest(url="http://test.com", method="GET")
        resp = TestResponse(
            status_code=200,
            headers={},
            body="x" * 1000,
            elapsed_ms=100,
        )

        evidence = Evidence.from_request_response(req, resp, "sig", max_body_length=100)

        assert len(evidence.response_body_snippet) < 120  # 100 + "...[truncated]"


class TestBudgetManager:
    def test_shared_origin_scan_budgets_and_reset(self):
        manager = BudgetManager(default_max_requests=3)
        manager.reserve("scan-a", "https://one.test/a")
        manager.reserve("scan-a", "https://one.test/b?x=1")
        assert manager.used("scan-a", "https://one.test") == 2
        with pytest.raises(BudgetExhaustedError):
            manager.reserve("scan-a", "https://one.test/c", amount=2)
        manager.reserve("scan-b", "https://one.test/c")
        manager.reserve("scan-a", "https://two.test/c")
        assert manager.used("scan-b", "https://one.test") == 1
        manager.reset_all()
        assert manager.used("scan-a", "https://one.test") == 0


class TestSignature:
    def test_string_match(self):
        sig = Signature(pattern="error", description="Error keyword")

        assert sig.matches("This is an error message")
        assert not sig.matches("Everything is fine")

    def test_case_insensitive(self):
        sig = Signature(pattern="ERROR", description="Error", case_sensitive=False)

        assert sig.matches("this has error")
        assert sig.matches("THIS HAS ERROR")

    def test_case_sensitive(self):
        sig = Signature(pattern="ERROR", description="Error", case_sensitive=True)

        assert sig.matches("this has ERROR")
        assert not sig.matches("this has error")

    def test_regex_match(self):
        sig = Signature(
            pattern=r"SQL syntax.*MySQL",
            description="MySQL error",
            is_regex=True,
        )

        assert sig.matches("You have an error in your SQL syntax; check MySQL manual")
        assert not sig.matches("PostgreSQL error")


class TestSignatureMatcher:
    def test_multiple_matches(self):
        signatures = [
            Signature(pattern="error1", description="First"),
            Signature(pattern="error2", description="Second"),
        ]
        matcher = SignatureMatcher(signatures)

        text = "This has error1 and error2"
        matches = matcher.match(text)

        assert len(matches) == 2

    def test_first_match(self):
        signatures = [
            Signature(pattern="first", description="First"),
            Signature(pattern="second", description="Second"),
        ]
        matcher = SignatureMatcher(signatures)

        text = "This has second and first"
        match = matcher.first_match(text)

        assert match is not None
        assert match.description == "First"  # First in list, not first in text

    def test_no_match(self):
        signatures = [Signature(pattern="nomatch", description="None")]
        matcher = SignatureMatcher(signatures)

        assert matcher.first_match("different text") is None

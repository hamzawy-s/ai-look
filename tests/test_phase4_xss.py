from adapters.adapter2.framework import Evidence
from adapters.adapter2.xss import XSSContext, XSSEncoding, XSSDetectionResult, XSSDetector


def test_reflection_without_browser_execution_is_only_candidate():
    detector = XSSDetector(None, None)
    detection = XSSDetectionResult(
        XSSContext.HTML_BODY, XSSEncoding.NONE, 0.9,
        "<img src=x onerror=window.__ailook_marker=1>", "html_body",
        [Evidence(
            "https://example.test/search?q=x", "GET", {}, None, 200, {},
            "<img src=x onerror=window.__ailook_marker=1>", "reflected syntax", 5,
        )],
    )
    candidate = detector._create_xss_candidate("https://example.test/search", "q", detection)
    assert candidate.finding_type == "XSS"
    assert candidate.verification_required == "browser execution instrumentation"
    assert candidate.confidence == 0.9

"""Advanced, non-persistent Cross-Site Scripting detection adapter."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, quote, unquote, urlparse

from .framework import (
    AdapterScanResult,
    BaseVulnerabilityAdapter,
    Evidence,
    Payload,
    PayloadType,
    TestRequest,
    TestResponse,
    aggregate_coverage,
    response_is_analyzable,
)
from .models import TestOutcome


class XSSContext(Enum):
    HTML_BODY = "HTML_BODY"
    HTML_ATTRIBUTE = "HTML_ATTRIBUTE"
    JAVASCRIPT_STRING = "JAVASCRIPT_STRING"
    JAVASCRIPT_CODE = "JAVASCRIPT_CODE"
    URL_PARAMETER = "URL_PARAMETER"
    UNKNOWN = "UNKNOWN"


class XSSEncoding(Enum):
    NONE = "NONE"
    URL = "URL"
    HTML_ENTITY = "HTML_ENTITY"
    HTML_ENTITY_DEC = "HTML_ENTITY_DEC"
    UNICODE = "UNICODE"
    DOUBLE_URL = "DOUBLE_URL"
    BASE64 = "BASE64"
    HEX = "HEX"


@dataclass(frozen=True)
class CspAssessment:
    allows_inline: bool
    reason: str


class CspAnalyzer:
    """Conservative static assessment of inline-script policy."""

    def analyze(self, headers: Dict[str, str], context: XSSContext = XSSContext.JAVASCRIPT_CODE) -> CspAssessment:
        policies = [value for key, value in headers.items()
                    if key.lower() == "content-security-policy" and value]
        if not policies:
            return CspAssessment(True, "no CSP header")
        context_directive = (
            "script-src-attr" if context == XSSContext.HTML_ATTRIBUTE
            else "script-src-elem"
        )
        decisions = []
        for policy in policies:
            directives = {}
            for part in policy.split(";"):
                tokens = part.strip().split()
                if tokens:
                    directives.setdefault(tokens[0].lower(), tokens[1:])
            sources = directives.get(context_directive)
            effective = context_directive
            if sources is None:
                sources = directives.get("script-src")
                effective = "script-src"
            if sources is None:
                sources = directives.get("default-src")
                effective = "default-src"
            if sources is None:
                decisions.append((True, "policy has no script directive"))
                continue
            has_nonce_or_hash = any(
                token.lower().startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                for token in sources
            )
            if "'unsafe-inline'" in [token.lower() for token in sources] and not has_nonce_or_hash:
                decisions.append((True, f"{effective} permits unsafe-inline"))
            elif has_nonce_or_hash:
                decisions.append((False, f"{effective} has nonce/hash; unsafe-inline is ignored"))
            else:
                decisions.append((False, f"{effective} does not permit unsafe-inline"))
        allowed = all(item[0] for item in decisions)
        return CspAssessment(allowed, "; ".join(item[1] for item in decisions))


@dataclass
class XSSDetectionResult:
    context: XSSContext
    encoding: XSSEncoding
    confidence: float
    payload_used: str
    reflected_in: str
    evidence_list: List[Evidence]
    csp_bypass: bool = False
    csp_assessment: Optional[CspAssessment] = None

    @property
    def is_vulnerable(self) -> bool:
        return self.confidence >= 0.5


class XSSDetector(BaseVulnerabilityAdapter):
    """Detect reflected and DOM-based XSS with bounded probes."""

    def __init__(
        self,
        request_engine: Any,
        scope_engine: Any,
        max_requests_per_target: int = 150,
        max_concurrent_requests: int = 3,
        *,
        budget_manager=None,
        scan_id=None,
        waf_classifier=None,
    ):
        super().__init__(
            request_engine, scope_engine, max_requests_per_target,
            max_concurrent_requests,
            budget_manager=budget_manager,
            scan_id=scan_id,
            waf_classifier=waf_classifier,
        )
        self.payloads_by_context = {
            XSSContext.HTML_BODY: [
                ("<script>alert(1)</script>", XSSEncoding.NONE),
                ("<img src=x onerror=alert(1)>", XSSEncoding.NONE),
                ("<svg onload=alert(1)>", XSSEncoding.NONE),
                ("<input onfocus=alert(1) autofocus>", XSSEncoding.NONE),
                ("<details open ontoggle=alert(1)>", XSSEncoding.NONE),
                ("<img src=x onerror=al&#101;rt(1)>", XSSEncoding.HTML_ENTITY_DEC),
                ("<img src=x onerror=al%65rt(1)>", XSSEncoding.URL),
                ("<script src=\"data:text/javascript,alert(1)\"></script>",
                 XSSEncoding.NONE),
            ],
            XSSContext.HTML_ATTRIBUTE: [
                ('" autofocus onfocus=alert(1)//', XSSEncoding.NONE),
                ('" onmouseover="alert(1)', XSSEncoding.NONE),
                ('" onclick="alert(1)', XSSEncoding.NONE),
            ],
            XSSContext.JAVASCRIPT_STRING: [
                ("';alert(1)//", XSSEncoding.NONE),
                ('";alert(1)//', XSSEncoding.NONE),
                ("</script><script>alert(1)</script>", XSSEncoding.NONE),
            ],
            XSSContext.JAVASCRIPT_CODE: [
                ("alert(1)", XSSEncoding.NONE),
                ("};alert(1);//", XSSEncoding.NONE),
            ],
        }
        self.csp_analyzer = CspAnalyzer()

    def _detect_context(self, baseline_response, payload):
        body = baseline_response.body
        if payload not in body and quote(payload, safe="") not in body:
            return XSSContext.UNKNOWN
        index = body.find(payload)
        if index < 0:
            payload = quote(payload, safe="")
            index = body.find(payload)
        window = body[max(0, index - 100):index + len(payload) + 100].lower()
        if "<script" in window and "</script>" not in window[index:]:
            return XSSContext.JAVASCRIPT_STRING if any(
                marker in window for marker in ("'", '"', "`")
            ) else XSSContext.JAVASCRIPT_CODE
        if re.search(r"<[^>]+\s+[a-z-]+=['\"][^'\"]*" +
                     re.escape(payload), window, re.IGNORECASE):
            return XSSContext.HTML_ATTRIBUTE
        return XSSContext.HTML_BODY

    async def detect_reflected_xss(
        self, url: str, parameter: str, baseline_response: TestResponse
    ) -> Optional[XSSDetectionResult]:
        for context, payloads in self.payloads_by_context.items():
            for value, encoding in payloads:
                encoded = self._apply_encoding(value, encoding)
                request = TestRequest(
                    url=url,
                    params={parameter: encoded},
                    payload=Payload(
                        encoded, PayloadType.REFLECTED,
                        description=f"XSS {context.value} ({encoding.value})",
                    ),
                )
                attempt = await self.execute_request(request)
                if not attempt.ok:
                    self._capture_attempt(attempt)
                    continue
                response = attempt.response
                if not response_is_analyzable(response):
                    continue
                reflection = self._check_reflection(value, encoded, response.body)
                if not reflection["reflected"] or not self._is_dangerous_reflection(
                    value, reflection["reflection_context"], response.body
                ):
                    continue
                actual_context = {
                    "html_attribute": XSSContext.HTML_ATTRIBUTE,
                    "script_tag": XSSContext.JAVASCRIPT_STRING,
                }.get(reflection["reflection_context"], context)
                csp = self.csp_analyzer.analyze(response.headers, actual_context)
                evidence = Evidence.from_request_response(
                    request, response,
                    f"XSS reflected in {reflection['reflection_context']}",
                )
                evidence = Evidence(**{**evidence.__dict__,
                    "contextual_analysis": f"CSP for {actual_context.value}: {csp.reason}; inline_allowed={csp.allows_inline}"})
                return XSSDetectionResult(
                    context=context,
                    encoding=encoding,
                    confidence=self._calculate_xss_confidence(
                        value, reflection, response
                    ),
                    payload_used=encoded,
                    reflected_in=reflection["reflection_context"],
                    evidence_list=[evidence],
                    csp_bypass=self._is_csp_bypass(value),
                    csp_assessment=csp,
                )
        return None

    async def detect_dom_xss(self, url: str, parameter: str):
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            base += f"?{parsed.query}"
        for value in (
            "#<img src=x onerror=alert(1)>",
            "#javascript:alert(1)",
            "#'-alert(1)-'",
        ):
            request = TestRequest(
                url=base + value,
                payload=Payload(value, PayloadType.REFLECTED,
                                description="DOM-based XSS probe"),
            )
            attempt = await self.execute_request(request)
            if not attempt.ok:
                self._capture_attempt(attempt)
                continue
            response = attempt.response
            sinks = (
                "document.write", "innerhtml", "outerhtml",
                "insertadjacenthtml", "eval(", "settimeout(",
                "setinterval(", "function(",
            )
            # A static sink without demonstrated source-to-sink data flow is not
            # exploit evidence. Preserve it only as an explicit candidate signal.
            if response_is_analyzable(response) and any(sink in response.body.lower() for sink in sinks):
                csp = self.csp_analyzer.analyze(response.headers, XSSContext.JAVASCRIPT_CODE)
                evidence = Evidence.from_request_response(request, response, "DOM source/sink static candidate")
                evidence = Evidence(**{**evidence.__dict__,
                    "contextual_analysis": f"CSP for {XSSContext.JAVASCRIPT_CODE.value}: {csp.reason}; inline_allowed={csp.allows_inline}"})
                return XSSDetectionResult(
                    XSSContext.JAVASCRIPT_CODE,
                    XSSEncoding.NONE,
                    0.6,
                    value,
                    "URL fragment",
                    [evidence],
                    csp_assessment=csp,
                )
        return None

    def _apply_encoding(self, payload, encoding):
        if encoding == XSSEncoding.NONE:
            return payload
        if encoding == XSSEncoding.URL:
            return quote(payload, safe="")
        if encoding == XSSEncoding.DOUBLE_URL:
            return quote(quote(payload, safe=""), safe="")
        if encoding == XSSEncoding.HTML_ENTITY:
            return "".join(f"&#x{ord(char):x};" for char in payload)
        if encoding == XSSEncoding.HTML_ENTITY_DEC:
            return "".join(f"&#{ord(char)};" for char in payload)
        return payload

    def _check_reflection(self, original_payload, encoded_payload, response_body):
        result = {
            "reflected": False,
            "reflection_context": "unknown",
            "exact_match": False,
            "encoded_match": False,
        }
        reflected = None
        if original_payload in response_body:
            result["exact_match"] = True
            reflected = original_payload
        elif encoded_payload in response_body:
            result["encoded_match"] = True
            reflected = encoded_payload
        elif unquote(encoded_payload) in response_body:
            result["encoded_match"] = True
            reflected = unquote(encoded_payload)
        if reflected is not None:
            result["reflected"] = True
            result["reflection_context"] = self._get_reflection_context(
                reflected, response_body
            )
        return result

    def _get_reflection_context(self, payload, response_body):
        index = response_body.find(payload)
        if index < 0:
            return "unknown"
        window = response_body[max(0, index - 200):index + len(payload) + 200]
        lower = window.lower()
        relative = index - max(0, index - 200)
        script_start, script_end = lower.find("<script"), lower.find("</script>")
        if script_start >= 0 and script_end >= 0 and script_start < relative < script_end:
            return "script_tag"
        if re.search(r"<[^>]+\s+[a-z-]+=['\"][^'\"]*" +
                     re.escape(payload), window, re.IGNORECASE):
            return "html_attribute"
        if "<!--" in window and "-->" in window:
            start, end = window.find("<!--"), window.find("-->")
            if start < relative < end:
                return "html_comment"
        return "html_body"

    def _is_dangerous_reflection(self, payload, reflection_context, response_body):
        lower = payload.lower()
        if "<script" in lower and reflection_context != "html_comment":
            return True
        if any(handler in lower for handler in (
            "onerror", "onload", "onclick", "onmouseover", "onfocus",
        )) and "=" in payload:
            return True
        return "javascript:" in lower or "data:text/html" in lower

    def _calculate_xss_confidence(self, payload, reflection_check, response):
        confidence = 0.3
        if reflection_check["exact_match"]:
            confidence += 0.2
        if reflection_check["reflection_context"] in ("script_tag", "html_attribute"):
            confidence += 0.2
        if "<script" in payload.lower():
            confidence += 0.15
        elif any(handler in payload.lower() for handler in ("onerror", "onload", "onclick")):
            confidence += 0.1
        if response.status_code in (403, 503):
            confidence *= 0.5
        return min(confidence, 1.0)

    def _is_csp_bypass(self, payload):
        return any(pattern in payload.lower() for pattern in (
            "data:text/javascript", "base href", "cdn.jsdelivr.net",
            "//attacker.com",
        ))

    def _create_xss_candidate(self, url, parameter, result):
        if not result.evidence_list:
            return None
        evidence = list(result.evidence_list)
        return self.make_candidate(
            finding_type="XSS", target=url, parameter=parameter, method="GET",
            technique="reflected-syntax-candidate", confidence=result.confidence,
            evidence=evidence,
            reason="reflected syntax requires instrumented browser execution to confirm exploitability",
        )

    async def _scan_parameter_legacy(self, url, parameter):
        baseline_attempt = await self.execute_request(TestRequest(
            url=url, params={parameter: "test_baseline"}
        ))
        if not baseline_attempt.ok:
            self._capture_attempt(baseline_attempt)
            return None
        baseline = baseline_attempt.response
        if not response_is_analyzable(baseline):
            self._scan_problem_outcome = TestOutcome.INCONCLUSIVE
            self._scan_problem_reason = "baseline response was incomplete or undecodable"
            return None
        reflected = await self.detect_reflected_xss(url, parameter, baseline)
        if reflected and reflected.is_vulnerable:
            return self._create_xss_candidate(url, parameter, reflected)
        dom = await self.detect_dom_xss(url, parameter)
        if dom and dom.is_vulnerable:
            return self._create_xss_candidate(url, parameter, dom)
        return None

    async def scan_parameter(self, url, parameter, original_value=None):
        if not self._is_authorized(url, "GET"):
            return AdapterScanResult([], [], TestOutcome.SKIPPED,
                                     "scope rejected before test execution", 0)
        if self.request_engine is None or not callable(getattr(self.request_engine, "send_request", None)):
            return AdapterScanResult([], [], TestOutcome.ERROR,
                                     "request engine unavailable", 0)
        self._scan_problem_outcome = None
        self._scan_problem_reason = None
        candidate = await self._scan_parameter_legacy(url, parameter)
        return AdapterScanResult(
            findings=[], candidates=[candidate] if candidate else [],
            coverage_outcome=(TestOutcome.INCONCLUSIVE if candidate else self._scan_problem_outcome or TestOutcome.ABSENT),
            reason=candidate.reason if candidate else self._scan_problem_reason or "completed analyzable probes without a candidate",
            evidence_count=len(candidate.evidence) if candidate else 0,
        )

    async def scan(self, target_url, parameters=None):
        if parameters is None:
            parameters = list(parse_qs(urlparse(target_url).query).keys())
        items = list(parameters.items()) if isinstance(parameters, dict) else [(p, None) for p in parameters]
        candidates, outcomes = [], []
        for parameter, value in items:
            result = await self.scan_parameter(target_url, parameter, value)
            candidates.extend(result.candidates)
            outcomes.append(result.coverage_outcome)
        return AdapterScanResult(
            findings=[], candidates=candidates,
            coverage_outcome=TestOutcome.INCONCLUSIVE if candidates else aggregate_coverage(outcomes),
            reason="XSS probes completed" if items else "no query parameters to test",
            evidence_count=sum(len(candidate.evidence) for candidate in candidates),
        )

# Phase 6 Security Audit — Reflected XSS Verification

## 1. Verdict and scope

Phase 6 adds a caller-invoked workflow for safe reflected XSS verification. It screens one or more GET query parameters with a unique inert marker, then tests only candidates reflected as a uniquely parsed HTML body text node. A candidate becomes a Core Finding only after a fresh isolated Chromium context executes the exact generated proof script and the verifier reads the matching per-attempt token from the top-level page.

The workflow does not start from `main.py`. It does not use the legacy alert-style XSS probe list. Reflection, context inference, and a browser-created element alone never confirm XSS.

**Supported:** explicitly scoped HTTP(S) GET endpoints without a query or fragment, conservative query parameter names, `text/html` responses, and a marker identified as an HTML body text node. Only the same candidate identity, target, parameter, method, technique, confidence, proof token, complete request telemetry, and successful cleanup may pass the promotion gate.

**Deferred:** stored, blind, out-of-band, DOM-only, upload, POST, authenticated, attribute, JavaScript-string, JSON, SVG/MathML, template, and other contexts; crawler behavior; WAF bypass; browser exploitation; persistent payloads; and state-changing requests.

## 2. Architecture and lifecycle

`AssessmentOrchestrator.assess_xss(detector, parameters)` is the explicit entry point. It requires the detector to use the assessment's exact `RequestEngine`, `ScopeEngine`, shared `BudgetManager`, and `scan_id`. The caller's original values are not sent or retained. The detector substitutes a unique inert `AILOOKREFLECT` marker and records reflection evidence as a `DetectionCandidate` only.

The marker context parser is deliberately conservative. Only one unique marker parsed as HTML body text in a `text/html` response proceeds to browser verification. The verifier creates a separate Chromium process and fresh context for that candidate, then injects a 192-bit unique token through a local-only script that assigns a property on the current `window`. No callback, storage write, network request, file access, or destructive action is in the proof script. Browser confirmation requires both an exact parsed instance of that script in the main HTML response and an exact token read from the page's main frame.

Verification outcomes are `VERIFIED`, `NOT_VERIFIED`, `INCONCLUSIVE`, `NOT_TESTED`, `BLOCKED`, and `ERROR`. A non-verified candidate stays in the candidate collection. A non-confirming single proof attempt does not label the candidate a false positive. Only `VERIFIED` can enter the existing `FindingsPipeline`, and the finding keeps the candidate's confidence unchanged and requires human review. Ordinary `add_result()` submissions cannot inject an XSS Finding around this gate.

The JSON report adds `xss_verification_reports` and links each report outcome/reason to its candidate fingerprint. There is no HTML report renderer in the current repository. Reports retain the proof token hash, not its raw value; browser request query values are redacted; no full browser response is added to a verification report.

## 3. Threat model

The returned page and every script it contains are treated as hostile. A tested page may attempt to:

- create subresource, frame, popup, worker, fetch, or WebSocket requests;
- redirect the browser, use a non-HTTP scheme, or create delayed/background activity;
- exploit ambient cookies, storage, proxy configuration, or browser DNS;
- produce response sizes, hangs, or errors that exhaust the verifier; or
- make unrelated page behavior appear to be proof of the current candidate.

The verifier protects the host and scan boundary by using a separate headless browser process with the Chromium sandbox requested, no reused profile, a fresh context, no saved credentials, no accepted downloads, blocked service workers, and bounded process/context/navigation/request/response handling. The browser context is closed and the browser process is shut down for each verification. An incomplete route, unexpected page activity, blocked navigation, timeout, truncation, startup error, or cleanup failure cannot promote a candidate.

## 4. Browser networking and scope boundary

The browser never uses its own HTTP transport. A context-wide route is installed before creating the page. Each HTTP(S) request must be a GET, pass the existing scope check, reserve from the assessment's shared budget and concurrency gate through `BaseVulnerabilityAdapter.execute_request`, and complete through the existing `RequestEngine`. That engine retains its URL validation, DNS resolution and IP validation, DNS rebinding defenses, pinned IP transport, TLS validation, redirect configuration, response bound, timeout, and `trust_env=False` behavior. Only bounded, decoded text resources are returned to Chromium. Sensitive credentials, cookies, hop-by-hop headers, and `Set-Cookie` are not forwarded.

The initial document request and all HTTP(S) scripts, frames, styles, images, fetches, XHR, popup requests, and worker requests use this same route. Every out-of-scope HTTP request is logged and aborted before DNS lookup. Each allowed HTTP request consumes one reservation. WebSocket attempts are separately scope checked, budgeted when in scope, logged, and blocked without connecting to an upstream server. Non-HTTP frame navigation is recorded using only its scheme, the page is closed, and telemetry is marked incomplete so the proof cannot be accepted.

Redirect following is disabled on every browser-generated RequestEngine call. A 3xx response is not fulfilled to Chromium because the browser can automatically follow redirects returned by a route fulfillment. Instead, the destination is resolved relative to the source, scope checked, recorded with `followed=false`, and the source response is aborted. Even an authorized redirect remains inconclusive for this workflow.

Chromium is launched with `--no-proxy-server`, a host resolver rule that fails all browser-side DNS resolution, background network/component update features disabled, QUIC disabled, WebRTC disabled, and WebTransport/peer-connection APIs removed in each page. Browser HTTP routes can still fulfill from the RequestEngine without browser-side DNS. A restrictive CSP policy is appended as an additional policy to each HTML response; existing response CSP is preserved and remains enforced. The added policy permits the inline proof script and HTTP(S) resources that still pass the route, blocks unsupported resource classes/schemes, disallows objects, and applies a browser sandbox. The context has an ephemeral empty storage state and receives no cookies or saved identity.

The controls rely on Playwright's documented context-wide routing behavior, its requirement to block service workers for complete interception, its WebSocket routing API, and the browser's automatic redirect behavior. These are pinned and exercised by the real-browser tests. See [Playwright BrowserContext routing](https://playwright.dev/python/docs/api/class-browsercontext#browser-context-route), [BrowserContext WebSocket routing](https://playwright.dev/python/docs/api/class-browsercontext#browser-context-route-web-socket), and [BrowserContext service-worker option](https://playwright.dev/python/docs/api/class-browser#browser-new-context-option-service-workers).

### Bounds

- At most 32 browser HTTP routes are processed per candidate.
- The RequestEngine's configured response cap remains the transport read limit. The verifier serves at most 1 MiB per browser resource and 2 MiB total; keep `RequestConfig.max_response_bytes` at or below 1 MiB when that same strict read cap is required. The repository's Phase 6 integration engine uses 1 MiB.
- Each RequestEngine call is limited to 3 seconds; browser navigation is limited to 8 seconds; page actions and post-proof network idle are separately bounded.
- Playwright startup, browser launch, context setup, context close, browser close, and driver stop are each bounded.
- Concurrent HTTP work uses the shared per-scan `BudgetManager` semaphore.

## 5. Security review

### Independent security review

The first pass identified five implementation and test-hardening issues:

1. A worker request could race with page load and be missed by the first test run. Verification now waits on a bounded Playwright `networkidle` condition before taking its telemetry snapshot. Three consecutive real Chromium worker test runs passed after this change.
2. An unexpected context-close exception could skip later browser and Playwright shutdown attempts. Cleanup now attempts context close, browser close, and driver stop independently; any failure keeps the report non-promotable. A real-browser cleanup-failure test confirms exact proof cannot promote when context cleanup fails.
3. HTTP routing alone does not observe local scheme navigations such as a `data:` frame. HTML responses now receive a restrictive additional CSP policy, and any non-HTTP(S) frame navigation is recorded with a sanitized scheme marker, closes the page, and makes request telemetry incomplete. A controlled Chromium test exercises this path.
4. Candidate screening evidence carried a marker hash but the verifier initially did not compare it to the marker. The verifier now checks the exact SHA-256 before browser startup; a regression confirms mismatched evidence causes zero browser or network requests.
5. A hostile response could place credential-like values in a `Content-Type` parameter. Candidate metadata and browser request records now sanitize that header before retention.

The review also checked scope checks before RequestEngine use, DNS/IP pinning reuse, redirect suppression, query redaction, worker and WebSocket handling, unique proof tokens, exact candidate matching, confidence preservation, candidate retention, response truncation, and the finding gate. No confirmed scope bypass or promotion bypass remains in the reviewed change set.

### Test-quality review

The positive test runs the actual pinned headless Chromium binary against a local loopback fixture through the real `RequestEngine`; it checks the observed proof, candidate match, confidence, finding evidence, cleanup, and budget counts. The security matrix uses only local fixtures; `outside.invalid` is a non-routable test name and tests assert the resolver is never called for denied destinations. Redirect, worker, WebSocket, subresource budget, DNS failure/rebinding, timeout, response truncation, stale token, browser startup, cleanup failure, concurrent limits, unsupported contexts, and report linkage are checked. Startup and cleanup failure cases patch the Playwright launch/close boundary while keeping the rest of the actual browser lifecycle active.

The worker case was specifically hardened against timing flakiness and passed three consecutive development runs after the bounded idle wait was added; the final Phase 6 suite also passed with the same-origin HTTP worker fixture. No public targets or callback services are used.

## 6. Files changed

Added:

- `adapters/adapter2/xss_verification.py` — structured reports and single-use isolated browser verifier.
- `tests/test_phase6_xss_verification.py` — local real-browser security and lifecycle matrix.
- `docs/phase6-audit.md` — this audit.

Modified:

- `adapters/adapter2/xss.py` — inert-marker safe screen; legacy entry points remain separate.
- `adapters/adapter2/orchestrator.py` — explicit `assess_xss()` flow and matching-report-only promotion gate.
- `reporting/reporter.py` — JSON XSS verification reporting and candidate linkage.
- `tests/local_vulnerable_app.py` — controlled local endpoints for browser and network-policy cases.
- `requirements.txt` and `requirements-dev.txt` — pinned Playwright package.
- `README.md` — Phase 6 setup, scope, status, and limitations.

`core_engine.py`, `adapters/adapter2/scope.py`, and `adapters/adapter2/request.py` remain unchanged. Phase 6 adds no competing finding lifecycle and no alternate HTTP client.

## 7. Validation results

Environment: Windows, Python 3.10.11, project `.venv`, pinned Playwright with local Chromium runtime. The accepted merged Phase 5 baseline completed before implementation with 294 passed tests, zero failures, zero skips, no warnings, and successful compilation.

Final validation was run from the repository `.venv` on Windows with Python 3.10.11. Pytest reported no warnings, skips, or failures.

| Run | Result |
|---|---|
| Accepted baseline before Phase 6 | 294 passed |
| Phase 6 focused suite | 25 passed in 35.35s; 0 failed, 0 skipped, no warnings |
| Phase 5 SQLi verification | 51 passed in 26.96s; 0 failed, 0 skipped, no warnings |
| Scope, context, RequestEngine, budget, and adapter framework tests | 169 passed in 0.84s; 0 failed, 0 skipped, no warnings |
| Complete `tests/` suite | 319 passed in 64.80s; 0 failed, 0 skipped, no warnings |
| `python -m compileall -q core_engine.py adapters reporting tests` | Passed |
| Real Chromium positive integration | Passed; exact proof observed and matching candidate promoted with original confidence |

## 8. Known limitations and remaining risk

- Only the specific reflected HTML body text-node strategy is supported. A non-executing proof result means only that this bounded strategy did not confirm execution.
- Browser use is unauthenticated. No browser cookies, login state, custom client certificates, proxy credentials, or saved profile are accepted.
- CSP hardening can change page behavior. The original response policy remains in effect; page features excluded by the added policy may make an attempt inconclusive or not representative of a normal browser session.
- Non-HTTP document activity is not a supported verification path. The page is closed and cannot be promoted if such navigation is detected. The browser is still isolated and all HTTP(S) is routed through RequestEngine.
- Keep the shared RequestEngine response cap configured at or below 1 MiB if the strict Phase 6 transport-read cap is needed; Phase 6 never serves a larger response to Chromium.
- Browser binary installation and execution are platform-dependent. A missing or incompatible runtime blocks verification; it does not fall back to direct browser networking or a weaker proof.
- The implementation has no HTML report renderer and no automatic scan runner.

## 9. Git delivery

The Phase 6 implementation is isolated on `phase6/reflected-xss-verification`, based on the merged `main` branch at `dbac55f5fdb9ad42cff8927b372a94fc78feee38`. Feature commit: `4f53680` (`feat: implement safe reflected XSS verification`). The delivery is local to this branch; it was not pushed, merged, or opened as a pull request. The final documentation commit and working-tree state are reported in the delivery summary.

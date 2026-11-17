# Phase 5 Audit — Safe SQL Injection Verification

**Status:** Implementation and independent reviews complete; all review findings are resolved. Windows regression and compile validation passed. Phase 5 acceptance is pending commit and remote branch verification.

## 1. Repository recovery and baseline

- Non-Git source snapshot: `D:\AI Look`.
- Git checkout: `C:\Users\Hamza\Documents\Codex\2026-11-16\files-pasted-by-the-user-act\work\ai-look`.
- The Git checkout was fast-forwarded from local `main` to the accepted Phase 4 commit `e851aa24d317006c42903bb9392355e98618a8ed`, then the implementation branch `phase5/sqli-verification` was created.
- The snapshot and Git checkout matched for 62 of 65 compared source files; the three differences were whitespace-only blank lines. The protected files matched the accepted Phase 4 Git blobs.
- Baseline on Windows 10 / Python 3.10.11: **243 passed**; `compileall` passed. The run used the existing `D:\AI Look\.venv` environment, pytest 9.2.0, pytest-asyncio 1.5.0, httpx 0.28.1, httpcore 1.0.9, pydantic 2.14.3, and aiosqlite 0.22.1.

## 2. Architecture and supported invocation

Phase 4 has no automatic scan runner. The supported production entry point is `AssessmentOrchestrator.assess_sqli(detector, parameters)`, explicitly called by the application that owns the scan. It runs the safe screen and verifier in one workflow; `main.py` does not invoke it.

The caller must provide one target, scan ID, scope engine, Phase 3 `RequestEngine`, and scan-wide `BudgetManager` through `AdapterContext`. The same engine, scope, budget object, and scan ID must be passed to `SQLiDetector`. The entry point rejects detectors with time-based or UNION probes enabled, validates every parameter and original value before detector requests begin, and calls only `scan_parameter_safe()`. That method uses three interleaved repetitions of baseline and `AND` TRUE/FALSE controls. It never calls the legacy error-based quote-breakout or OR probe path. A complete, stable screen without the required differential yields `ABSENT`; a suggestive differential creates a candidate for a separate repeated verification sequence. Final persistence/report generation remains in the existing `finalize()` path.

No additional HTTP client or transport is created. Every screening and verification exchange uses `BaseVulnerabilityAdapter.execute_request` and therefore the existing scope, request engine, atomic budget reservation, concurrency, timeout, size, decode, and redaction controls.

## 3. Verification design

`SQLiVerifier` handles only SQL injection candidates with GET query parameters and supported original-value grammars. Its fixed strategy is `repeated_boolean_differential_v1`: three complete rounds, each containing one baseline, TRUE, and FALSE observation. The round order rotates (`baseline/true/false`, `true/false/baseline`, `false/baseline/true`) to reduce ordering bias. Nine successful exchanges are required for a conclusion.

Payloads are read-only Boolean conditions. Numeric values receive `AND 1=1` / `AND 1=2`; single-quoted strings receive a quote close followed by `AND '1'='1` / `AND '1'='2`. Time-delay and UNION verification are not used. The verifier does not call an LLM or use timing or response length as proof.

`VERIFIED` requires all nine responses to be usable and stable within their respective groups, uniform successful 2xx statuses, baseline and TRUE normalized bodies equal, and FALSE different. A complete usable sequence that does not meet that rule is `NOT_CONFIRMED`; this means only that the defined Boolean procedure did not confirm the candidate.

## 4. Original-value validation

Validation occurs before payload construction or network activity:

- Numeric literals use `-?(0|[1-9][0-9]{0,8})(\.[0-9]{1,6})?`.
- Bare single-quoted string contents use `[A-Za-z_][A-Za-z0-9_]{0,63}` and reject ambiguous SQL words such as `OR`, `SELECT`, and `NULL`.
- Parameter names use `[A-Za-z_][A-Za-z0-9_.-]{0,63}`.
- Only HTTP(S) targets without query, fragment, or userinfo are supported.

Operators, whitespace, quote breakout, comments, statement separators, exponent forms, unsupported punctuation, and compound expressions are outside these grammars. Unsupported input or context returns `NOT_TESTED` with zero requests.

## 5. Response comparison and evidence

Normalization converts CRLF/CR to LF, collapses whitespace, trims surrounding whitespace, and replaces exact original/injected input values and their raw, HTML-escaped, and URL-encoded forms with a fixed marker. No timestamps, identifiers, arbitrary fragments, or length-only signals are normalized.

If a TRUE/FALSE Boolean expression appears in a response in raw, HTML-escaped, or URL-encoded form, the sequence is `INCONCLUSIVE`; this prevents a reflected control from creating a differential. Each repetition group must be byte-content-stable after the stated normalization. Random IDs and other changing content remain visible and make the result inconclusive.

Every required response must be non-empty, complete, decoded, untruncated, and status-comparable. Empty, missing, undecodable, truncated, incomplete, varying-status, or non-2xx responses cannot support either a positive or negative conclusion. WAF interference, timeout, and mid-sequence budget exhaustion are inconclusive. Transport failures are errors. Scope rejection or insufficient initial budget is not tested.

Reports store the stable candidate fingerprint, finding fingerprint, target and parameter, strategy/context, planned and completed repetitions, request count, comparison booleans, per-sample status and completeness/decode metadata, response length, SHA-256 of the normalized body, error category, reason, and additional verification requirements. An attempted request without a response still has a sample record. Full response bodies are not retained in verification reports. URLs and candidate evidence use the existing redaction helpers.

## 6. Confidence, promotion, and coverage

Verification outcome is separate from statistical confidence. The Core Finding preserves the candidate's existing confidence; `VERIFIED` is not described as a probability. Promoted findings are marked `PRESENT`, `HIGH` severity, and `requires_human_review=True`.

Only a `VERIFIED` report whose candidate fingerprint matches the stored candidate authorizes promotion into the existing Core pipeline. Ordinary `add_result()` submissions reject SQLi Findings. Non-verified candidates remain separate and retain their detection evidence and linked outcome/reason; they do not enter AI finding tasks.

Coverage maps a complete `NOT_CONFIRMED` result to `ABSENT`; `VERIFIED` maps to `PRESENT`; incomplete evidence maps to `INCONCLUSIVE`, `SKIPPED`, or `ERROR` as appropriate. Safe-screen candidates are initially recorded as inconclusive, so they cannot cause an absent result. A no-candidate `ABSENT` requires the entire nine-request safe screen to complete with nonempty, decoded, untruncated, same-status, stable groups. Existing coverage precedence and Core lifecycle/persistence are reused.

Candidate identity includes finding type, target, parameter, method, and technique. Candidate storage deduplicates exact identities and preserves different techniques separately. Verification reports are attached to the matching candidate fingerprint; verified candidates cannot be reintroduced through ordinary result submission. The ordinary Finding gate recognizes normalized SQLi aliases, including `SQLi`.

## 7. Budget and scope behavior

The safe screening stage and verifier each preflight that nine reservations remain. A positive workflow can therefore use up to 18 reservations (nine for screening and nine for verification). Each individual exchange still reserves budget atomically through the shared execution path. Insufficient initial budget is `NOT_TESTED`; exhaustion after exchanges begin is `INCONCLUSIVE`. Scope is checked before the preflight and again by the execution path. Phase 5 requests override redirect following to `False`, even when the shared RequestEngine is configured to follow redirects. A 3xx response remains inconclusive and no redirect hop can exceed the per-request reservation. Other adapter requests retain the engine's configured redirect policy.

## 8. Independent review

- **Security Review:** completed. It found three issues: legacy orchestration still sent quote-breakout/OR detector probes; a configured redirect could make one budget reservation perform multiple HTTP exchanges; and a `Finding(type="SQLi")` alias bypassed the ordinary SQLi Finding gate. Resolutions: `assess_sqli()` now calls the AND-only repeated `scan_parameter_safe()` path; Phase 5 `TestRequest`s disable following per request and `RequestEngine` exposes a per-call override; and the normalized type gate recognizes `SQLI` and `SQLINJECTION`. Regression tests prove no legacy probes are sent, a 9-reservation redirect run creates exactly 9 local HTTP requests, and the `SQLi` alias is rejected.
- **Test Review:** completed. It found two coverage gaps: no negative test for a VERIFIED report linked to a different candidate fingerprint, and no Phase 5 orchestration test against parameterized SQLite. Added a mismatched-fingerprint promotion/persistence regression and a seeded-candidate `assess_sqli()` test that runs the real verifier and RequestEngine against the real parameterized SQLite fixture. No independence defects or additional code defects were reported.

## 9. Validation results

Environment: Windows 10, Python 3.10.11, pytest 9.2.0, pytest-asyncio 1.5.0, httpx 0.28.1, httpcore 1.0.9, pydantic 2.14.3, aiosqlite 0.22.1. Test output reported no skips or warnings.

| Run | Result |
|---|---|
| Phase 4 baseline before implementation | 243 passed |
| Focused `tests/test_phase5_sqli_verification.py` | 51 passed in 26.77s |
| Full `tests/` regression suite | 294 passed in 30.02s; 0 failed, 0 skipped |
| `python -m compileall -q core_engine.py adapters reporting tests` | Passed |

The controlled loopback integration tests use the real Phase 3 RequestEngine. They cover vulnerable numeric and single-quoted SQLite queries, a parameterized negative control, end-to-end orchestration and promotion, rejected values with zero request activity, empty and incomplete bodies, reflection, dynamic responses, status and transport failures, timeouts, redirects, budgets, scope, cancellation, concurrency, candidate identity, reporting, and lifecycle coverage.

## 10. Protected files

Two protected files remain byte-identical to the accepted baseline:

- `core_engine.py`
- `adapters/adapter2/scope.py`

`adapters/adapter2/request.py` has one narrowly scoped exception. The security reviewer reproduced an authorized same-scope redirect with `follow_redirects=True`: the verifier reported 9 reservations while the local server received 18 HTTP requests. Since `BudgetManager` reserves once per adapter call and the Phase 3 engine follows redirect hops internally, this could exceed the request budget. A per-call `follow_redirects` override was added to `RequestEngine`, and Phase 5 requests explicitly disable following without mutating shared engine configuration. The regression uses a budget of 9, a redirect-enabled engine, and asserts the server receives exactly 9 requests and the budget records exactly 9. Existing global redirect policy remains unchanged for requests without an override.

## 11. Limitations and deferred work

- Supported contexts are limited to conservative numeric literals and conservative single-quoted string contents. Double-quoted, backtick, parenthesized, LIKE, and other contexts are not supported.
- The integration fixture demonstrates SQLite behavior only; other DBMS compatibility is not established.
- `NOT_CONFIRMED` is bounded to this strategy and does not prove that all SQLi techniques are absent.
- Phase 5 does not follow redirects. Redirecting endpoints remain inconclusive; redirect behavior is still available to other adapters through the shared RequestEngine configuration.
- Normalization deliberately avoids removing arbitrary dynamic content; endpoints that emit changing content may remain inconclusive.
- `assess_sqli()` is caller-invoked. No scan CLI or service currently runs it automatically.
- No time-based or UNION verification, database extraction/enumeration, writes, stacked statements, OOB behavior, XSS browser verification, or active SSRF/LFI/CMDi workflows were added.

## 12. Git delivery

The implementation is isolated on `phase5/sqli-verification`, based on accepted Phase 4 `e851aa24d317006c42903bb9392355e98618a8ed`. The required feature commit and remote branch hash will be recorded here after delivery.

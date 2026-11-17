# AI Look Phase 4 status

## Execution and result flow

Implemented adapters send requests through `BaseVulnerabilityAdapter.execute_request`, which checks scope and engine availability before atomically reserving the shared scan/origin budget, applies the per-scan concurrency gate, then calls the injected Phase 3 `RequestEngine`. A multi-adapter scan creates one `BudgetManager` and injects that same object into each detector; all implemented detectors use the same default concurrency cap. The result mapping retains status, completion, truncation, decoding, final URL, pinned IP, timeout, and transport information. Scope or engine rejection does not consume budget. No adapter-specific request sender or request counter remains.

Adapter output flows through `AdapterScanResult` into `AssessmentOrchestrator`. The orchestrator records deduplicated coverage with the existing `CoverageCollector`, sends only confirmed Core `Finding` objects through the existing `FindingsPipeline`, and retains `DetectionCandidate` objects in a distinct candidate list for reporting. The JSON assessment report includes candidate evidence, verification requirements, and per-test coverage records. Candidate objects are type-checked and never enter Core persistence or confirmed-finding AI analysis. Coverage precedence prevents ABSENT from replacing PRESENT, INCONCLUSIVE, BLOCKED, ERROR, or SKIPPED observations. Duplicate finding and candidate output is deduplicated.

## Adapter status

| Component | Status |
|---|---|
| Request framework and budgets | One request path; thread-safe per-scan/per-origin reservations, per-scan concurrency control, fail-closed origin handling, and response metadata preservation. |
| SQLi | Candidate-only. Probes retain the supplied parameter value. Time-based candidates require three paired control/delay samples for a recognized DBMS and reject failed, incomplete, truncated, undecoded, or unstable results. SQLite tests exercise a real vulnerable query and a parameterized control; this does not establish compatibility with other DBMS engines. |
| XSS | Candidate-only until browser execution is verified. Evidence records whether reflection was exact or encoded, its inferred context, and context-specific CSP assessment with directive fallback and nonce/hash handling. Static JavaScript or DOM sink observations do not prove execution or source-to-sink exploitability. |
| WAF | Harmless baseline, query-marker, and header-marker requests only. Vendor or block signatures support an informational observation; an HTTP status by itself does not. |
| Assessment orchestration | Connects adapter results to coverage, existing Core persistence/lifecycle, and separate candidate reporting. |
| SSRF | `SKIPPED`. Requires an owned, allowlisted callback receiver and bounded interaction wait before controlled verification. No metadata or internal-service requests are sent. |
| LFI | `SKIPPED`. Requires a temporary, test-owned sentinel file and verification limited to that fixture. No system-file probes are sent. |
| CMDi | `SKIPPED`. Requires a controlled fixture with a bounded, deterministic verification signal. No arbitrary command probes are sent. |
| Browser verification | Deferred. Requires browser execution instrumentation (for example, a project-approved browser runner); candidate-only reporting remains available without it. |

`core_engine.py`, `adapters/adapter2/scope.py`, and `adapters/adapter2/request.py` are preserved. Phase 0–3 behavior is checked separately from the Phase 4 tests. No Phase 5 work is included.

## Validation

The original Phase 4 validation used the repository's Windows `.venv` (Python 3.10.11): 242 tests collected and passed, 34 focused Phase 4 tests passed, and 208 Phase 0–3 plus established adapter regression tests passed. During GitHub synchronization, a remote-only Core fingerprint test was retained and updated to the current `DeduplicationEngine` API. The combined repository then collected and passed 243 tests; `compileall` passed. The TLS cases that failed in the earlier Linux review passed in this Windows run. Localhost integration tests use the actual Phase 3 `RequestEngine` with loopback explicitly enabled only in those test instances.

The workspace has no `.git` directory, so Git status and a repository diff are unavailable. The final report lists changed and added files directly.

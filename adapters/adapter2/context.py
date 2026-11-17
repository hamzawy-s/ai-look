from __future__ import annotations

from typing import Any, Optional

from core_engine import DeduplicationEngine

from .coverage import CoverageCollector
from .models import AdapterContext
from .scope import ScopeEngine


_DEFAULT = object()


def create_context(
    *,
    project_id: str,
    scan_id: str,
    scan_date: str,
    target_url: str,
    scope: Any = _DEFAULT,
    scope_config: Optional[dict] = None,
    request_engine: Any = None,
    budget_manager: Any = None,
    coverage: Any = None,
    dedup_engine: Any = None,
) -> AdapterContext:
    """Runtime AdapterContext factory (Phase 2).

    Distinguishes three cases via the _DEFAULT sentinel:
      * scope omitted  -> build a ScopeEngine from scope_config (deny-all if absent)
      * scope=None     -> keep explicit None (no authorization -> fail closed)
      * explicit scope -> use it verbatim

    No HTTP client is created here; request_engine is injected by the caller.
    """
    if scope is _DEFAULT:
        scope_engine = ScopeEngine(**(scope_config or {}))
    else:
        scope_engine = scope

    dedup = dedup_engine if dedup_engine is not None else DeduplicationEngine()
    cov = coverage if coverage is not None else CoverageCollector(dedup, scan_id)

    return AdapterContext(
        project_id=project_id,
        scan_id=scan_id,
        scan_date=scan_date,
        target_url=target_url,
        scope_engine=scope_engine,
        request_engine=request_engine,
        budget_manager=budget_manager,
        coverage=cov,
        dedup_engine=dedup,
    )

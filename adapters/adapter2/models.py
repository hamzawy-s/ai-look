from __future__ import annotations

from enum import Enum
from typing import Any, List, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, Field


class TestOutcome(str, Enum):
    __test__ = False

    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
    INCONCLUSIVE = "INCONCLUSIVE"


EXECUTED_OUTCOMES = frozenset({TestOutcome.PRESENT, TestOutcome.ABSENT})


class CoverageRecord(BaseModel):
    fingerprint: str
    input_id: str
    test_family: str
    outcome: TestOutcome
    method: Optional[str] = None
    target: str
    finding_type: str
    parameter: str
    parameter_location: str = "QUERY"
    evidence: List[str] = Field(default_factory=list)
    request_fingerprint: Optional[str] = None
    scan_id: str
    reason: Optional[str] = None


@runtime_checkable
class ScopeEngineProtocol(Protocol):
    def is_authorized(self, url: str, method: str = "GET") -> bool:
        ...


class AdapterContext(BaseModel):
    project_id: str
    scan_id: str
    scan_date: str
    target_url: str
    scope_engine: Any = None
    request_engine: Any = None
    coverage: Any = None
    dedup_engine: Any = None
    budget_manager: Any = None

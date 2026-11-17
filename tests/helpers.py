from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core_engine import Finding, Severity

from adapters.adapter2.base import BaseAdapter
from adapters.adapter2.context import _DEFAULT, create_context
from adapters.adapter2.models import AdapterContext, TestOutcome


def step(
    outcome: TestOutcome,
    *,
    param: str = "id",
    finding_type: str = "SQL_INJECTION",
    target: str = "/api/users",
    family: str = "SQLI",
    method: str = "GET",
) -> Dict[str, Any]:
    return {
        "outcome": outcome,
        "param": param,
        "type": finding_type,
        "target": target,
        "family": family,
        "method": method,
    }


class FakeScope:
    def __init__(
        self,
        allowed: bool = True,
        allowed_hosts: Optional[set] = None,
    ):
        self.allowed = allowed
        self.allowed_hosts = (
            {host.lower() for host in allowed_hosts}
            if allowed_hosts is not None
            else None
        )
        self.calls: List[tuple] = []

    def is_authorized(self, url: str, method: str = "GET") -> bool:
        self.calls.append((url, method))
        if self.allowed_hosts is not None:
            host = (urlparse(url).hostname or "").lower()
            return host in self.allowed_hosts
        return self.allowed


class FakeEngine:
    def __init__(self):
        self.calls: List[tuple] = []

    async def send_request(self, method: str, url: str, **kwargs: Any) -> None:
        self.calls.append((method, url))
        return None


def ctx(
    *,
    scope: Any = _DEFAULT,
    engine: Any = None,
    target_url: str = "https://t.local/api/users",
) -> AdapterContext:
    return create_context(
        project_id="p1",
        scan_id="s1",
        scan_date="2026-01-01T00:00:00Z",
        target_url=target_url,
        scope=scope,
        scope_config={
            "allowed_hosts": {"t.local"},
            "allowed_schemes": {"https"},
            "allowed_path_prefixes": ("/",),
        },
        request_engine=engine if engine is not None else FakeEngine(),
    )


class StubAdapter(BaseAdapter):
    def __init__(self, context: AdapterContext, plan: List[Dict[str, Any]]):
        super().__init__(context)
        self.plan = plan

    async def execute(self) -> None:
        if not self.is_authorized(self.context.target_url):
            return
        if self.context.request_engine is not None:
            await self.context.request_engine.send_request(
                "GET", self.context.target_url
            )
        for item in self.plan:
            self.record_coverage(
                input_id=item["param"],
                test_family=item["family"],
                outcome=item["outcome"],
                target=item["target"],
                finding_type=item["type"],
                parameter=item["param"],
                method=item.get("method", "GET"),
                evidence=["stub"],
            )
            if item["outcome"] == TestOutcome.PRESENT:
                self.add_finding(
                    Finding(
                        type=item["type"],
                        target=item["target"],
                        parameter=item["param"],
                        method=item.get("method", "GET"),
                        severity=Severity.HIGH,
                        confidence=0.9,
                        source="STUB",
                        evidence=["stub"],
                    )
                )
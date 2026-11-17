"""Backward-compatible facade over the Phase 3 shared Request Engine.

The previous implementation owned a second ``httpx.AsyncClient`` with
``follow_redirects=True``, no scope authorization, no DNS pinning, implicit
``trust_env=True`` (environment proxies), unbounded response buffering and a
``**kwargs`` passthrough that could override TLS verification. That is an
authorization bypass path, so this module now delegates to the single
canonical engine in ``adapters.adapter2.request``.

Behaviour changes (intentional, security fixes):
* ``request()`` returns a ``RequestResult`` instead of a raw ``httpx.Response``.
* ``follow_redirects`` is engine-controlled and disabled by default.
* Without an explicit ``scope`` (or ``engine``), every request is DENIED
  with ``error_category="scope"``. There is no permissive fallback.
* Unknown keyword arguments are rejected instead of forwarded to HTTPX.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from adapters.adapter2.request import (
    RequestConfig,
    RequestEngine,
    RequestResult,
    Resolver,
)

__all__ = ["AsyncRequestCore"]


class AsyncRequestCore:
    """Legacy entry point kept for compatibility; owns no HTTP client itself."""

    def __init__(
        self,
        timeout: float = 15.0,
        *,
        scope: Any = None,
        config: Optional[RequestConfig] = None,
        resolver: Optional[Resolver] = None,
        engine: Optional[RequestEngine] = None,
    ) -> None:
        if engine is not None:
            if not isinstance(engine, RequestEngine):
                raise TypeError("engine must be a RequestEngine")
            self._engine = engine
            self._owns_engine = False
        else:
            if config is None:
                overall = float(timeout)
                if overall <= 0:
                    raise ValueError("timeout must be a positive number")
                config = RequestConfig(
                    connect_timeout=min(5.0, overall),
                    read_timeout=overall,
                    write_timeout=overall,
                    pool_timeout=min(5.0, overall),
                )
            self._engine = RequestEngine(scope, config=config, resolver=resolver)
            self._owns_engine = True

    @property
    def engine(self) -> RequestEngine:
        return self._engine

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        content: Any = None,
        timeout: Any = None,
    ) -> RequestResult:
        return await self._engine.send_request(
            method, url, headers=headers, content=content, timeout=timeout
        )

    async def send_request(
        self,
        method: str = "GET",
        url: str = "",
        *,
        headers: Optional[Dict[str, str]] = None,
        content: Any = None,
        timeout: Any = None,
    ) -> RequestResult:
        return await self._engine.send_request(
            method, url, headers=headers, content=content, timeout=timeout
        )

    async def close(self) -> None:
        if self._owns_engine:
            await self._engine.aclose()

    async def aclose(self) -> None:
        await self.close()

    async def __aenter__(self) -> "AsyncRequestCore":
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.close()

"""Thread-safe in-memory request budgets shared by adapters in a scan."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import threading
from dataclasses import dataclass
from typing import Dict
from urllib.parse import urlparse


class BudgetExhaustedError(ValueError):
    """Raised when a request cannot be reserved."""


class InvalidBudgetOriginError(ValueError):
    """Raised when a URL cannot identify a valid HTTP origin."""


def target_origin(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise InvalidBudgetOriginError("url must be a non-empty string")
    try:
        parsed = urlparse(url.strip())
    except ValueError as exc:
        raise InvalidBudgetOriginError(f"invalid url origin: {url!r}") from exc
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise InvalidBudgetOriginError(f"unsupported scheme for budget origin: {scheme!r}")
    if not parsed.netloc or "@" in parsed.netloc:
        raise InvalidBudgetOriginError("origin must not contain userinfo and must include a host")
    try:
        host = (parsed.hostname or "").rstrip(".").lower()
    except ValueError as exc:
        raise InvalidBudgetOriginError(f"invalid host in url: {url!r}") from exc
    if not host:
        raise InvalidBudgetOriginError(f"url has no parseable host: {url!r}")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        if len(host) > 253 or not host.isascii() or not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*", host
        ):
            raise InvalidBudgetOriginError(f"invalid hostname in url: {url!r}")
    try:
        port = parsed.port
    except ValueError:
        raise InvalidBudgetOriginError(f"invalid port in url: {url!r}")
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme, 0)
    if port <= 0 or port > 65535:
        raise InvalidBudgetOriginError(f"invalid port {port!r} in url: {url!r}")
    try:
        ipaddress.ip_address(host)
        is_ipv6 = ":" in host
    except ValueError:
        is_ipv6 = False
    formatted_host = f"[{host}]" if is_ipv6 else host
    return f"{scheme}://{formatted_host}:{port}"


@dataclass(frozen=True)
class BudgetKey:
    scan_id: str
    origin: str


class BudgetManager:
    """Manage per-scan, per-origin request budgets atomically."""

    def __init__(
        self,
        default_max_requests: int = 100,
        default_max_requests_per_target: int | None = None,
    ):
        limit = (
            default_max_requests
            if default_max_requests_per_target is None
            else default_max_requests_per_target
        )
        self._validate_limit(limit, "default_max_requests")
        self.default_max = int(limit)
        self._default_limit = self.default_max
        self._limits: Dict[BudgetKey, int] = {}
        self._used: Dict[BudgetKey, int] = {}
        self._semaphores = {}
        self._semaphore_limits = {}
        self._lock = threading.RLock()

    @staticmethod
    def _validate_scan_id(scan_id):
        if not isinstance(scan_id, str) or not scan_id.strip():
            raise ValueError("scan_id must be a non-empty string")

    @staticmethod
    def _validate_limit(limit, name="limit"):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError(f"{name} must be a positive integer")

    @staticmethod
    def _validate_amount(amount):
        if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
            raise ValueError("amount must be a positive integer")

    def reset_all(self):
        with self._lock:
            self._used.clear()
            self._limits.clear()

    def semaphore_for(self, scan_id: str, limit: int) -> asyncio.Semaphore:
        """Return the shared in-flight request gate for a scan."""
        self._validate_scan_id(scan_id)
        self._validate_limit(limit, "max_concurrent_requests")
        with self._lock:
            existing = self._semaphores.get(scan_id)
            if existing is not None:
                if self._semaphore_limits[scan_id] != limit:
                    raise ValueError("all adapters in one scan must use the same concurrency limit")
                return existing
            semaphore = asyncio.Semaphore(limit)
            self._semaphores[scan_id] = semaphore
            self._semaphore_limits[scan_id] = limit
            return semaphore

    def set_limit(self, scan_id: str, origin_or_url: str, limit: int):
        self._validate_scan_id(scan_id)
        self._validate_limit(limit)
        key = BudgetKey(scan_id, target_origin(origin_or_url))
        with self._lock:
            self._limits[key] = limit

    def reserve(self, scan_id: str, url: str, amount: int = 1) -> BudgetKey:
        self._validate_scan_id(scan_id)
        self._validate_amount(amount)
        key = BudgetKey(scan_id, target_origin(url))
        with self._lock:
            limit = self._limits.get(key, self._default_limit)
            used = self._used.get(key, 0)
            if used + amount > limit:
                raise BudgetExhaustedError(
                    f"request budget exhausted: scan_id={scan_id} "
                    f"origin={key.origin} used={used} limit={limit} requested={amount}"
                )
            self._used[key] = used + amount
        return key

    def try_reserve(self, scan_id: str, url: str, amount: int = 1) -> bool:
        try:
            self.reserve(scan_id, url, amount)
            return True
        except (BudgetExhaustedError, InvalidBudgetOriginError):
            return False

    def used(self, scan_id: str, url: str) -> int:
        self._validate_scan_id(scan_id)
        origin = target_origin(url)
        with self._lock:
            return self._used.get(BudgetKey(scan_id, origin), 0)

    def limit(self, scan_id: str, url: str) -> int:
        self._validate_scan_id(scan_id)
        key = BudgetKey(scan_id, target_origin(url))
        with self._lock:
            return self._limits.get(key, self._default_limit)

    def stats(self, scan_id: str):
        self._validate_scan_id(scan_id)
        with self._lock:
            return {
                key.origin: {"used": used, "limit": self._limits.get(key, self._default_limit)}
                for key, used in self._used.items()
                if key.scan_id == scan_id
            }

    def reset_scan(self, scan_id: str):
        self._validate_scan_id(scan_id)
        with self._lock:
            self._used = {key: value for key, value in self._used.items()
                          if key.scan_id != scan_id}
            self._limits = {key: value for key, value in self._limits.items()
                            if key.scan_id != scan_id}

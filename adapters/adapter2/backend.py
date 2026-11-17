"""Conservative passive backend fingerprinting (no network access)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class BackendSignal:
    technology: str
    source: str
    evidence: str


class BackendFingerprinter:
    """Extract explicit technology hints without treating absence as proof."""

    HEADER_RULES = (
        ("server", "nginx", "nginx"),
        ("server", "apache", "Apache HTTP Server"),
        ("server", "microsoft-iis", "Microsoft IIS"),
        ("x-powered-by", "php", "PHP"),
        ("x-powered-by", "asp.net", "ASP.NET"),
        ("x-powered-by", "express", "Express"),
        ("x-generator", "django", "Django"),
    )

    async def detect(self, response) -> List[BackendSignal]:
        headers: Dict[str, str] = getattr(response, "headers", {}) or {}
        normalized = {str(key).lower(): str(value) for key, value in headers.items()}
        signals = []
        for header, marker, technology in self.HEADER_RULES:
            value = normalized.get(header, "")
            if marker in value.lower():
                signals.append(BackendSignal(technology, f"header:{header}", value[:200]))
        return signals

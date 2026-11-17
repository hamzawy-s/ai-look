"""Signature matchers for vulnerability detection."""
import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Signature:
    """A pattern to match in responses."""

    pattern: str
    description: str
    is_regex: bool = False
    case_sensitive: bool = False
    severity_hint: str = "MEDIUM"

    def matches(self, text: str) -> bool:
        if self.is_regex:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            return bool(re.search(self.pattern, text, flags))
        if self.case_sensitive:
            return self.pattern in text
        return self.pattern.lower() in text.lower()


class SignatureMatcher:
    """Match multiple signatures against response."""

    def __init__(self, signatures: List[Signature]):
        self.signatures = signatures

    def match(self, text: str) -> List[Signature]:
        return [signature for signature in self.signatures if signature.matches(text)]

    def first_match(self, text: str) -> Optional[Signature]:
        matches = self.match(text)
        return matches[0] if matches else None


SQL_ERROR_SIGNATURES = [
    Signature(r"SQL syntax.*MySQL", "MySQL syntax error", True, severity_hint="HIGH"),
    Signature("Warning.*mysql_", "MySQL warning", True),
    Signature("unclosed quotation mark", "SQL Server error", severity_hint="HIGH"),
    Signature(r"ORA-[0-9]{5}", "Oracle error", True, severity_hint="HIGH"),
    Signature("PostgreSQL.*ERROR", "PostgreSQL error", True, severity_hint="HIGH"),
    Signature(r"sqlite(?:3)?\.(?:operational|database)error|sqlite error", "SQLite database error", True, severity_hint="HIGH"),
]

XSS_REFLECTION_SIGNATURES = [
    Signature("<script>", "Script tag reflection", severity_hint="HIGH"),
    Signature("onerror=", "Event handler reflection", severity_hint="HIGH"),
    Signature("javascript:", "JavaScript protocol", severity_hint="MEDIUM"),
]

LFI_SIGNATURES = [
    Signature("root:x:0:0:", "Linux passwd file", severity_hint="CRITICAL"),
    Signature("[boot loader]", "Windows boot.ini", severity_hint="HIGH"),
    Signature("<?php", "PHP source code", severity_hint="HIGH"),
]

WAF_SIGNATURES = [
    Signature("Cloudflare", "Cloudflare WAF", severity_hint="INFO"),
    Signature("AWS WAF", "AWS WAF", severity_hint="INFO"),
    Signature("ModSecurity", "ModSecurity", severity_hint="INFO"),
    Signature("Access denied", "Generic WAF block", severity_hint="INFO"),
]

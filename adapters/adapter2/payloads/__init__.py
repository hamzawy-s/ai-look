"""Conservative Phase 4 probe values.

These values are inert syntax indicators only. In particular, this module does
not include destructive SQL, operating-system file paths, shell commands,
metadata URLs, internal service URLs, alternate URL schemes, or external
callbacks. SSRF verification requires a separately configured allowlisted
callback service and therefore has no built-in destination payloads.
"""
from ..framework import Payload, PayloadType


SQLI_PAYLOADS = [
    Payload("'", PayloadType.ERROR_BASED, description="quote syntax indicator"),
    Payload('"', PayloadType.ERROR_BASED, description="double quote syntax indicator"),
    Payload("1 AND 1=1", PayloadType.BOOLEAN_BASED, description="true-condition candidate"),
    Payload("1 AND 1=2", PayloadType.BOOLEAN_BASED, description="false-condition candidate"),
]

XSS_PAYLOADS = [
    Payload("<ailook-marker>", PayloadType.REFLECTED, description="inert HTML context marker"),
    Payload('" ailook-marker="1', PayloadType.REFLECTED, description="inert attribute context marker"),
]

LFI_PAYLOADS = [
    Payload("../../ailook_fixture.txt", PayloadType.PATH_TRAVERSAL,
            description="controlled fixture path; requires a disposable test fixture"),
]

CMD_PAYLOADS = [
    Payload("; printf AILOOK_FIXED_MARKER", PayloadType.BENIGN,
            description="fixed harmless marker; use only in a disposable authorized fixture"),
]

SSRF_PAYLOADS = []

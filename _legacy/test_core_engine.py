import unittest
from core_engine import Finding, Severity, RequestDeduplicator

class CoreTests(unittest.TestCase):
    def test_fingerprint_is_stable(self):
        f = Finding(type="SQL_INJECTION", target="/api/users", method="GET", parameter="id", severity=Severity.HIGH, confidence=.9, source="test")
        engine = RequestDeduplicator()
        self.assertEqual(engine.finding_fingerprint(f), engine.fingerprint("GET", "/api/users", "SQL_INJECTION", "id"))

if __name__ == "__main__":
    unittest.main()

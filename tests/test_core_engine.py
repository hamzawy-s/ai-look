import unittest

from core_engine import DeduplicationEngine, Finding, Severity


class CoreTests(unittest.TestCase):
    def test_fingerprint_is_stable(self):
        finding = Finding(
            type="SQL_INJECTION", target="/api/users", method="GET",
            parameter="id", severity=Severity.HIGH, confidence=0.9, source="test",
        )
        engine = DeduplicationEngine()
        self.assertEqual(
            engine.generate_fingerprint(finding),
            engine.fingerprint_for("GET", "/api/users", "SQL_INJECTION", "id"),
        )


if __name__ == "__main__":
    unittest.main()

"""Regression orchestration interface."""
class RegressionAdapter:
    async def compare(self, previous_findings, current_findings):
        raise NotImplementedError("Use core lifecycle and coverage results to report regressions.")

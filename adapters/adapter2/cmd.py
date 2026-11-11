"""Command injection adapter interface."""
class CommandInjectionDetector:
    async def scan(self, request_context):
        raise NotImplementedError("Implement non-destructive command injection checks.")

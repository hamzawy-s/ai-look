"""Cross-site scripting adapter interface."""
class EnhancedXSSDetector:
    async def scan(self, request_context):
        raise NotImplementedError("Implement context-aware XSS verification.")

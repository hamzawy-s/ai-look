"""Local file inclusion adapter interface."""
class LFIDetector:
    async def scan(self, request_context):
        raise NotImplementedError("Implement safe, authorized LFI checks.")

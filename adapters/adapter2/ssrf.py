"""Server-side request forgery adapter interface."""
class SSRFDetector:
    async def scan(self, request_context):
        raise NotImplementedError("Implement controlled SSRF verification using an owned callback service.")

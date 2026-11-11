"""Web application firewall fingerprinting interface."""
class WAFDetector:
    async def detect(self, response):
        raise NotImplementedError("Add vendor-neutral WAF fingerprint rules.")

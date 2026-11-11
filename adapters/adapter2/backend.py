"""Backend technology fingerprinting interface."""
class BackendFingerprinter:
    async def detect(self, response):
        raise NotImplementedError("Add conservative framework and server fingerprint rules.")

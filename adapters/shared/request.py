"""Async HTTP request adapter shared by scanner modules."""
import httpx

class AsyncRequestCore:
    def __init__(self, timeout: float = 15.0):
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)

    async def request(self, method: str, url: str, **kwargs):
        return await self.client.request(method, url, **kwargs)

    async def close(self):
        await self.client.aclose()

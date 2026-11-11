"""Scan scheduling interface."""
class ScanScheduler:
    async def schedule(self, project_id: str, scan_config: dict):
        raise NotImplementedError("Connect to the chosen job scheduler.")

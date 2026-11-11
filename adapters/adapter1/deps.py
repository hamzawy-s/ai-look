"""Dependency and software composition analysis adapter interface."""
class DependencyAdapter:
    async def scan(self, manifest_path: str):
        raise NotImplementedError("Integrate an advisory database or dependency scanner.")

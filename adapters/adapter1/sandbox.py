"""Isolated sandbox adapter interface. Requires Docker and explicit authorization."""
class DockerSandbox:
    async def run(self, image: str, command: list[str], timeout: int = 60):
        raise NotImplementedError("Implement constrained Docker execution, resource limits, and cleanup.")

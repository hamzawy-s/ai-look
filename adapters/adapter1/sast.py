"""Static application security testing adapter interface."""
class SASTAdapter:
    async def scan(self, source_path: str):
        raise NotImplementedError("Integrate the selected SAST ruleset and emit core_engine.Finding objects.")

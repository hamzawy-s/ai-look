"""SQL injection adapter interface."""
class AdvancedSQLi:
    async def scan(self, request_context):
        raise NotImplementedError("Implement authorized SQLi checks and emit core_engine.Finding objects.")

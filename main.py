"""AI Look application entry point."""
import asyncio
from core_engine import FindingsPipeline

async def main():
    pipeline = FindingsPipeline(enable_ai=False)
    await pipeline.db.connect()
    try:
        print("AI Look core initialized. Connect authorized adapters in this entry point.")
    finally:
        await pipeline.close()

if __name__ == "__main__":
    asyncio.run(main())

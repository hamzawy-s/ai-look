"""In-process asynchronous event bus starter."""
import asyncio
from collections import defaultdict
from typing import Any, Callable

class EventBus:
    def __init__(self):
        self._handlers = defaultdict(list)

    def subscribe(self, event_name: str, handler: Callable[[dict[str, Any]], Any]):
        self._handlers[event_name].append(handler)

    async def publish(self, event_name: str, payload: dict[str, Any]):
        for handler in self._handlers[event_name]:
            result = handler(payload)
            if asyncio.iscoroutine(result):
                await result

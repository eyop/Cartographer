"""Base interface every source collector implements (week 2). Keeping this
tiny and uniform is what lets workers/tasks.py fan out with asyncio.gather
without a special case per source."""

from abc import ABC, abstractmethod

from ..models.entity import RawFinding


class BaseCollector(ABC):
    source_name: str

    @abstractmethod
    async def collect(self, target: str) -> list[RawFinding]:
        """Hit the source's API, return normalized-enough RawFinding objects.
        Must internally respect the source's rate limit (token bucket in Redis)."""
        raise NotImplementedError

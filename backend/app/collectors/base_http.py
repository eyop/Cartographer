"""Shared HTTP collector base (week 2).

Concrete collectors extend ``BaseHttpCollector`` which layers cache-check →
rate-limit-acquire → HTTP fetch → cache-write on top of the abstract
``BaseCollector`` interface.  Individual collectors only need to implement
``_fetch_raw`` (the actual API call) and optionally ``can_handle`` (to reject
targets outside their domain).
"""

from __future__ import annotations

import httpx
from redis.asyncio import Redis

from ..models.entity import RawFinding
from .base import BaseCollector
from .cache import ResponseCache
from .rate_limiter import RateLimiter


class BaseHttpCollector(BaseCollector):
    """Base for collectors that hit a REST API over HTTP.

    Subclasses set ``source_name`` and implement ``_fetch_raw``.
    """

    source_name: str = "base"

    def __init__(self, redis: Redis, http_client: httpx.AsyncClient):
        self.redis = redis
        self.http = http_client
        self.rate_limiter = RateLimiter(redis)
        self.cache = ResponseCache(redis)

    # -- subclasses implement this -------------------------------------------

    async def _fetch_raw(self, target: str) -> dict | None:
        """Make the actual API call and return the parsed JSON response.

        Return ``None`` if the target is out of scope or the API returns
        an empty / 404 result.  Raise ``httpx.HTTPError`` on transport issues.
        """
        raise NotImplementedError

    def can_handle(self, target: str, target_type: str) -> bool:
        """Gatekeeper — subclasses can override to reject unsuitable targets."""
        return True

    # -- shared orchestration ------------------------------------------------

    async def _get_cached(self, target: str) -> dict | None:
        return await self.cache.get(self.source_name, target)

    async def _set_cached(self, target: str, response: dict) -> None:
        await self.cache.set(self.source_name, target, response)

    async def collect(self, target: str) -> list[RawFinding]:
        """Full pipeline: cache → rate-limit → fetch → cache → RawFinding."""
        # 1. cache hit
        cached = await self._get_cached(target)
        if cached is not None:
            return [RawFinding(source=self.source_name, query=target, payload=cached)]

        # 2. rate-limit check
        bucket = self.rate_limiter.get(self.source_name)
        if not await bucket.acquire():
            # rate-limited — return empty so the pipeline doesn't stall
            return []

        # 3. fetch
        try:
            response = await self._fetch_raw(target)
        except httpx.HTTPError:
            return []

        if response is None:
            return []

        # 4. cache write
        await self._set_cached(target, response)

        # 5. raw finding
        return [RawFinding(source=self.source_name, query=target, payload=response)]

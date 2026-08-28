"""Redis response cache for raw API responses (week 3).

Caches the full JSON response body per source+query so repeated investigations
don't re-hit rate-limited APIs.  TTL varies by source — indexed Shodan host
data ages over hours; DNS records can change in minutes.

Key format: ``cache:{source}:{sha256(query)[:16]}``
"""

from __future__ import annotations

import hashlib
import json

from redis.asyncio import Redis

# Per-source TTL in seconds.
TTL_BY_SOURCE: dict[str, int] = {
    "shodan":      86_400,   # 24 h  — indexed host data is relatively stable
    "virustotal":  86_400,   # 24 h  — scan results don't change minute-to-minute
    "github":      3_600,    # 1 h   — repos evolve frequently
    "crtsh":      172_800,   # 48 h  — certs are append-only, slow to change
    "hibp":        86_400,   # 24 h  — breach dataset is effectively static
    "dns":           300,    # 5 m   — DNS records flip quickly
}


class ResponseCache:
    """Thin wrapper around Redis GET/SETEX with JSON (de)serialization."""

    def __init__(self, redis: Redis):
        self.redis = redis

    def _key(self, source: str, query: str) -> str:
        h = hashlib.sha256(query.encode()).hexdigest()[:16]
        return f"cache:{source}:{h}"

    async def get(self, source: str, query: str) -> dict | None:
        """Return the cached response dict, or None on miss."""
        raw = await self.redis.get(self._key(source, query))
        return json.loads(raw) if raw else None

    async def set(self, source: str, query: str, response: dict) -> None:
        """Store a response with the source-appropriate TTL."""
        ttl = TTL_BY_SOURCE.get(source, 3_600)
        await self.redis.setex(self._key(source, query), ttl, json.dumps(response))

    async def invalidate(self, source: str, query: str) -> None:
        """Explicitly drop a cache entry (e.g. after a cache-miss re-fetch)."""
        await self.redis.delete(self._key(source, query))

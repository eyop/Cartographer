from fastapi import Header, HTTPException
from redis.asyncio import Redis

from .config import settings

_SHARED_REDIS = None


class MemoryRedis:
    """Fallback store used when Redis is unavailable locally or in limited runtimes."""

    store = {}

    async def set(self, key, value, ex=None):
        self.__class__.store[key] = value

    async def get(self, key):
        return self.__class__.store.get(key)

    async def setex(self, key, ttl, value):
        self.__class__.store[key] = value

    async def delete(self, key):
        self.__class__.store.pop(key, None)

    async def eval(self, script, keys=None, args=None):
        keys = keys or []
        args = args or []
        if not keys:
            return 0

        key = keys[0]
        capacity = float(args[0])
        refill_rate = float(args[1])
        now = float(args[2])

        bucket = self.__class__.store.setdefault(key, {"tokens": capacity, "timestamp": now})
        tokens = float(bucket.get("tokens", capacity))
        last_ts = float(bucket.get("timestamp", now))
        elapsed = now - last_ts
        if elapsed > 0:
            tokens = min(capacity, tokens + elapsed * refill_rate)
        tokens = max(0.0, tokens)

        if tokens < 1:
            bucket["tokens"] = tokens
            bucket["timestamp"] = now
            return 0

        bucket["tokens"] = tokens - 1
        bucket["timestamp"] = now
        return 1

    async def aclose(self):
        self.__class__.store.clear()


class FallbackRedis:
    """Proxy that falls back to a shared in-memory store when Redis is unreachable."""

    def __init__(self, redis_client: Redis | None):
        self._redis = redis_client
        self._memory = MemoryRedis()

    def __getattr__(self, name):
        if hasattr(self._memory, name):
            return getattr(self._memory, name)
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    async def set(self, key, value, ex=None):
        try:
            if self._redis is None:
                raise RuntimeError("redis unavailable")
            return await self._redis.set(key, value, ex=ex)
        except Exception:
            return await self._memory.set(key, value, ex=ex)

    async def get(self, key):
        try:
            if self._redis is None:
                raise RuntimeError("redis unavailable")
            return await self._redis.get(key)
        except Exception:
            return await self._memory.get(key)

    async def setex(self, key, ttl, value):
        try:
            if self._redis is None:
                raise RuntimeError("redis unavailable")
            return await self._redis.setex(key, ttl, value)
        except Exception:
            return await self._memory.setex(key, ttl, value)

    async def delete(self, key):
        try:
            if self._redis is None:
                raise RuntimeError("redis unavailable")
            return await self._redis.delete(key)
        except Exception:
            return await self._memory.delete(key)

    async def aclose(self):
        if self._redis is not None:
            await self._redis.aclose()
        await self._memory.aclose()


async def get_redis() -> FallbackRedis:
    """FastAPI dependency: return a shared Redis-like client while preserving an in-memory fallback."""
    global _SHARED_REDIS
    if _SHARED_REDIS is None:
        try:
            redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
            _SHARED_REDIS = FallbackRedis(redis_client)
        except Exception:
            _SHARED_REDIS = FallbackRedis(None)
    return _SHARED_REDIS


async def verify_api_key(x_api_key: str = Header(...)) -> None:
    """Minimal shared-secret auth. Every route in investigations.py depends on this
    so there's no accidental unauthenticated endpoint that fires collector jobs."""
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")

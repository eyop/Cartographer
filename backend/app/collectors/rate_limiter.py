"""Redis-backed token-bucket rate limiter (week 2).

Each source gets a TokenBucket whose capacity and refill_rate match the API's
documented limits.  An atomic Lua script handles the refill-and-acquire step so
concurrent workers (or concurrent requests within one worker) share a single
limiting window without race conditions.

Usage::

    limiter = RateLimiter(redis)
    bucket = limiter.get("shodan")
    if not await bucket.acquire():
        # rate-limited this round — collector returns empty findings
        return []
"""

from __future__ import annotations

import time

from redis.asyncio import Redis

# Per-source limits.  Capacity = max burst tokens; refill_rate = tokens/sec.
# Values from each API's public rate-limit documentation.
SOURCE_LIMITS: dict[str, dict[str, float]] = {
    "shodan":      {"capacity": 1,  "refill_rate": 1 / 5},    # 1 req / 5 s
    "virustotal":  {"capacity": 4,  "refill_rate": 4 / 60},    # 4 reqs / min
    "github":      {"capacity": 29, "refill_rate": 29 / 60},   # ~30 reqs/min (auth)
    "crtsh":       {"capacity": 1,  "refill_rate": 1 / 1},     # no hard limit, be polite
    "hibp":        {"capacity": 1,  "refill_rate": 1 / 1.5},   # 1 req / 1.5 s
    "dns":         {"capacity": 20, "refill_rate": 20 / 1},   # local-ish, generous
}

# Lua script: atomically refill tokens based on elapsed wall-clock time, then
# consume one token if available.  Returns 1 on success, 0 if rate-limited.
# State stored in a Redis hash: { "tokens": float, "timestamp": epoch-float }.
_LUA_SCRIPT = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local data = redis.call('HMGET', key, 'tokens', 'timestamp')
local tokens = tonumber(data[1])
local last_ts = tonumber(data[2])

-- initialise bucket if first call
if tokens == nil then
    tokens = capacity
    last_ts = now
end

-- refill proportionally to elapsed time (token-bucket formula)
local elapsed = now - last_ts
if elapsed > 0 then
    tokens = math.min(capacity, tokens + elapsed * rate)
end
tokens = math.max(0, tokens)

if tokens < 1 then
    -- not enough tokens — store state and deny
    redis.call('HMSET', key, 'tokens', tokens, 'timestamp', now)
    redis.call('EXPIRE', key, 3600)
    return 0
end

tokens = tokens - 1
redis.call('HMSET', key, 'tokens', tokens, 'timestamp', now)
redis.call('EXPIRE', key, 3600)
return 1
"""


class TokenBucket:
    """A single source's rate-limit bucket backed by Redis."""

    def __init__(self, redis: Redis, key: str, capacity: float, refill_rate: float):
        self.redis = redis
        self.key = key
        self.capacity = capacity
        self.refill_rate = refill_rate

    async def acquire(self) -> bool:
        """Consume one token.  Returns True if allowed, False if rate-limited."""
        now = time.time()
        result = await self.redis.eval(
            _LUA_SCRIPT,
            keys=[self.key],
            args=[self.capacity, self.refill_rate, now],
        )
        return bool(result)


class RateLimiter:
    """Registry mapping source names to TokenBucket instances."""

    def __init__(self, redis: Redis):
        self.redis = redis

    def get(self, source: str) -> TokenBucket:
        limits = SOURCE_LIMITS.get(source, {"capacity": 10, "refill_rate": 10})
        return TokenBucket(
            redis=self.redis,
            key=f"ratelimit:{source}",
            capacity=limits["capacity"],
            refill_rate=limits["refill_rate"],
        )

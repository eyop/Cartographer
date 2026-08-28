from fastapi import Header, HTTPException
from redis.asyncio import Redis

from .config import settings


async def get_redis() -> Redis:
    """FastAPI dependency: one Redis connection per request via connection pool."""
    return Redis.from_url(settings.redis_url, decode_responses=True)


async def verify_api_key(x_api_key: str = Header(...)) -> None:
    """Minimal shared-secret auth. Every route in investigations.py depends on this
    so there's no accidental unauthenticated endpoint that fires collector jobs."""
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")

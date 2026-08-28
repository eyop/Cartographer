"""Thin wrapper around arq's connection pool. arq (not Celery) because it's
async-native — the collectors in week 2 are already asyncio, so the worker
can await them directly instead of bridging sync/async."""

from arq import create_pool
from arq.connections import RedisSettings

from ..config import settings

_pool = None


async def get_arq_pool():
    global _pool
    if _pool is None:
        _pool = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    return _pool

"""Thin wrapper around arq's connection pool. arq (not Celery) because it's
async-native — the collectors in week 2 are already asyncio, so the worker
can await them directly instead of bridging sync/async."""

from __future__ import annotations

from typing import Any

from arq import create_pool
from arq.connections import RedisSettings

from ..config import settings

_pool = None


class InMemoryJobQueue:
    """Local fallback used when Redis is unavailable in dev or limited environments."""

    def __init__(self):
        self.jobs: list[dict[str, Any]] = []

    async def enqueue_job(self, function_name: str, *args, **kwargs):
        job = {"function": function_name, "args": args, "kwargs": kwargs}
        self.jobs.append(job)
        return {"job_id": len(self.jobs), "function": function_name}


async def get_arq_pool():
    global _pool
    if _pool is None:
        try:
            _pool = await create_pool(RedisSettings.from_dsn(settings.redis_url))
        except Exception:
            _pool = InMemoryJobQueue()
    return _pool

"""Thin wrapper around arq's connection pool. arq (not Celery) because it's
async-native — the collectors in week 2 are already asyncio, so the worker
can await them directly instead of bridging sync/async."""

from __future__ import annotations

import asyncio
from typing import Any

from arq import create_pool
from arq.connections import RedisSettings

from ..config import settings

_pool = None


async def _run_in_memory_job(function_name: str, ctx: dict[str, Any], *args, **kwargs):
    if function_name == "run_investigation":
        from ..workers.tasks import run_investigation

        await run_investigation(ctx, *args, **kwargs)


class InMemoryJobQueue:
    """Local fallback used when Redis is unavailable in dev or limited environments."""

    def __init__(self):
        self.jobs: list[dict[str, Any]] = []

    async def enqueue_job(self, function_name: str, *args, **kwargs):
        job = {"function": function_name, "args": args, "kwargs": kwargs}
        self.jobs.append(job)

        ctx = kwargs.pop("ctx", None)
        remaining_args = list(args)
        if ctx is None and remaining_args and isinstance(remaining_args[0], dict) and "redis" in remaining_args[0]:
            ctx = remaining_args.pop(0)

        if ctx is not None:
            asyncio.create_task(_run_in_memory_job(function_name, ctx, *remaining_args, **kwargs))

        return {"job_id": len(self.jobs), "function": function_name}


async def get_arq_pool():
    global _pool
    if _pool is None:
        try:
            _pool = await create_pool(RedisSettings.from_dsn(settings.redis_url))
        except Exception:
            _pool = InMemoryJobQueue()
    return _pool

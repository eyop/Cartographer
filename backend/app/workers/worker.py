"""arq worker entrypoint. Run with: arq app.workers.worker.WorkerSettings"""

from arq.connections import RedisSettings
from redis.asyncio import Redis

from ..config import settings
from ..dependencies import FallbackRedis
from .tasks import run_investigation


async def startup(ctx):
    ctx["redis"] = FallbackRedis(Redis.from_url(settings.redis_url, decode_responses=True))


async def shutdown(ctx):
    await ctx["redis"].aclose()


class WorkerSettings:
    functions = [run_investigation]
    redis_settings = RedisSettings.from_dsn(settings.redis_url)
    max_jobs = settings.max_concurrent_jobs  # cap concurrent investigations, not just per-source calls
    on_startup = startup
    on_shutdown = shutdown

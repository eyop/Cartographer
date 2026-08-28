"""The actual investigation pipeline (week 2-4).

This is the arq job function — it ties together collectors -> normalization
-> synthesis.  Real logic lives in those modules; this stays orchestration-only.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime

import httpx

from ..collectors import CollectorManager, RawFinding, normalize
from ..models.investigation import InvestigationStatus
from ..synthesis.chain import synthesize_threat_profile

RESULT_TTL = 60 * 60 * 24


async def run_investigation(ctx, investigation_id: str, target: str, target_type: str):
    redis = ctx["redis"]
    await _update_status(redis, investigation_id, InvestigationStatus.running)

    progress: dict[str, str] = {}

    try:
        # 1. Fan out to collectors relevant to this target_type
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as http:
            manager = CollectorManager(redis, http)
            collectors = manager.get_collectors(target, target_type)

            if not collectors:
                raise ValueError(f"No collectors available for target_type='{target_type}'")

            # Run all collectors concurrently (each is internally rate-limited)
            raw_results = await asyncio.gather(
                *[collector.collect(target) for collector in collectors],
                return_exceptions=True,
            )

            # Merge results, tracking per-source progress
            all_findings: list[RawFinding] = []
            for collector, result in zip(collectors, raw_results):
                if isinstance(result, Exception):
                    progress[collector.source_name] = f"error: {str(result)[:120]}"
                else:
                    all_findings.extend(result)
                    progress[collector.source_name] = f"{len(result)} findings"

            await _update_status(
                redis, investigation_id, InvestigationStatus.running, progress=progress
            )

        # 2. Normalize raw findings into entity/relationship graph
        progress["phase"] = "normalizing"
        await _update_status(
            redis, investigation_id, InvestigationStatus.running, progress=progress
        )
        graph = normalize(all_findings)

        # 3. Synthesize threat profile via LangChain/OpenAI
        progress["phase"] = "synthesizing"
        await _update_status(
            redis, investigation_id, InvestigationStatus.running, progress=progress
        )
        threat_profile = await synthesize_threat_profile(target, graph, all_findings)

        # 4. Store results in Redis
        await redis.set(
            f"investigation:{investigation_id}:result",
            json.dumps({"threat_profile": threat_profile.model_dump(), "graph": graph}),
            ex=RESULT_TTL,
        )
        progress["phase"] = "completed"
        await _update_status(
            redis, investigation_id, InvestigationStatus.completed, progress=progress
        )

    except Exception as e:
        progress["phase"] = "failed"
        await _update_status(
            redis, investigation_id, InvestigationStatus.failed,
            error=str(e), progress=progress,
        )
        raise


async def _update_status(
    redis,
    investigation_id: str,
    status: InvestigationStatus,
    error: str | None = None,
    progress: dict[str, str] | None = None,
) -> None:
    """Update an InvestigationRecord in Redis: status, error, progress."""
    key = f"investigation:{investigation_id}"
    data = await redis.get(key)
    record = json.loads(data) if data else {}
    record["status"] = status.value
    record["updated_at"] = datetime.utcnow().isoformat()
    if error:
        record["error"] = error
    if progress:
        record.setdefault("progress", {})
        record["progress"].update(progress)
    await redis.set(key, json.dumps(record), ex=RESULT_TTL)

"""The actual investigation pipeline. This is the function arq calls — it's
the one place that ties together collectors (week 2) -> normalization
(week 3) -> synthesis (week 4). Keep it orchestration-only; real logic
lives in those modules so this stays readable."""

import json

from ..models.investigation import InvestigationStatus

# from ..collectors import shodan, github, dns, hibp, virustotal   # week 2
# from ..collectors.normalize import normalize                      # week 3
# from ..synthesis.chain import synthesize_threat_profile            # week 4

RESULT_TTL = 60 * 60 * 24


async def run_investigation(ctx, investigation_id: str, target: str, target_type: str):
    redis = ctx["redis"]
    await _update_status(redis, investigation_id, InvestigationStatus.running)

    try:
        # 1. fan out to collectors relevant to this target_type, rate-limited per source
        # raw_findings = await asyncio.gather(*[c.collect(target) for c in COLLECTORS[target_type]])

        # 2. normalize into the shared Entity/Relationship graph
        # graph = normalize(raw_findings)

        # 3. LangChain synthesis -> structured ThreatProfile with citations
        # profile = await synthesize_threat_profile(graph)

        # --- placeholder until weeks 2-4 modules are wired in ---
        profile = {"target": target, "summary": "stub profile — collectors not yet wired in", "risk_indicators": []}
        graph = {"entities": [], "relationships": []}
        # ----------------------------------------------------------

        await redis.set(
            f"investigation:{investigation_id}:result",
            json.dumps({"threat_profile": profile, "graph": graph}),
            ex=RESULT_TTL,
        )
        await _update_status(redis, investigation_id, InvestigationStatus.completed)

    except Exception as e:
        await _update_status(redis, investigation_id, InvestigationStatus.failed, error=str(e))
        raise


async def _update_status(redis, investigation_id: str, status: InvestigationStatus, error: str | None = None):
    key = f"investigation:{investigation_id}"
    data = await redis.get(key)
    record = json.loads(data) if data else {}
    record["status"] = status.value
    if error:
        record["error"] = error
    await redis.set(key, json.dumps(record), ex=RESULT_TTL)

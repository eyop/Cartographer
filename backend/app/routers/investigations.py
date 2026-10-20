"""Investigation API router — status, graph, profile, and PDF report endpoints."""

import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from ..dependencies import get_redis, verify_api_key
from ..models.entity import ThreatProfile
from ..models.investigation import InvestigationCreate, InvestigationRecord, TargetType
from ..services.job_queue import get_arq_pool
from ..services.report import render_report_pdf

router = APIRouter(
    prefix="/investigations",
    tags=["investigations"],
    dependencies=[Depends(verify_api_key)],
)


def _validate_target(target: str, target_type: TargetType) -> str:
    sanitized = target.strip()
    if not sanitized:
        raise HTTPException(status_code=400, detail="Target must not be empty")

    if target_type == TargetType.domain:
        if "@" in sanitized or sanitized.count(".") == 0:
            raise HTTPException(
                status_code=400,
                detail="Domain target should look like a domain like example.com",
            )
    elif target_type == TargetType.email:
        if "@" not in sanitized:
            raise HTTPException(
                status_code=400,
                detail="Email target must include an @ sign",
            )
    elif target_type == TargetType.company:
        if "@" in sanitized:
            raise HTTPException(
                status_code=400,
                detail="Company target should not look like an email address",
            )
    elif target_type == TargetType.person:
        if "@" in sanitized:
            raise HTTPException(
                status_code=400,
                detail="Person target should not look like an email address",
            )
    return sanitized


@router.post("", response_model=InvestigationRecord, status_code=202)
async def create_investigation(payload: InvestigationCreate, redis=Depends(get_redis)):
    """Kicks off an investigation and returns immediately (202). Collection +
    synthesis run as a background job — see workers/tasks.py — because a
    multi-source pull will blow past a synchronous request timeout."""
    if not payload.authorized:
        raise HTTPException(
            status_code=400,
            detail="You must confirm authorization to investigate this target",
        )

    sanitized = _validate_target(payload.target, payload.target_type)

    record = InvestigationRecord(target=sanitized, target_type=payload.target_type)
    await redis.set(f"investigation:{record.id}", record.model_dump_json(), ex=60 * 60 * 24)

    try:
        pool = await get_arq_pool()
        await pool.enqueue_job(
            "run_investigation",
            record.id,
            record.target,
            record.target_type.value,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Investigation queue unavailable: {exc}",
        ) from exc

    return record


@router.get("/{investigation_id}", response_model=InvestigationRecord)
async def get_investigation(investigation_id: str, redis=Depends(get_redis)):
    """Poll this for status. `progress` fills in per-source as collectors finish
    so the frontend can show something better than a bare spinner."""
    data = await redis.get(f"investigation:{investigation_id}")
    if not data:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return InvestigationRecord(**json.loads(data))


@router.get("/{investigation_id}/graph")
async def get_graph(investigation_id: str, redis=Depends(get_redis)):
    """Entity/relationship graph for the D3 view. 404 until synthesis finishes."""
    data = await redis.get(f"investigation:{investigation_id}:result")
    if not data:
        raise HTTPException(status_code=404, detail="Results not ready yet")
    return json.loads(data)["graph"]


@router.get("/{investigation_id}/profile", response_model=ThreatProfile)
async def get_profile(investigation_id: str, redis=Depends(get_redis)):
    """Structured threat profile (summary + risk indicators + entities + relationships)."""
    data = await redis.get(f"investigation:{investigation_id}:result")
    if not data:
        raise HTTPException(status_code=404, detail="Results not ready yet")
    result = json.loads(data)
    return ThreatProfile(**result["threat_profile"])


@router.get("/{investigation_id}/report")
async def get_report(investigation_id: str, redis=Depends(get_redis)):
    """Streams the PDF report for a completed investigation."""
    data = await redis.get(f"investigation:{investigation_id}:result")
    if not data:
        raise HTTPException(status_code=409, detail="Report not ready yet")
    result = json.loads(data)
    profile = ThreatProfile(**result["threat_profile"])
    pdf_bytes = await render_report_pdf(profile)
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=report_{investigation_id}.pdf"
        },
    )

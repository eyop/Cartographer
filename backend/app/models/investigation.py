import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class TargetType(str, Enum):
    domain = "domain"
    email = "email"
    company = "company"


class InvestigationStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class InvestigationCreate(BaseModel):
    target: str
    target_type: TargetType
    authorized: bool = Field(
        ...,
        description="Caller confirms they are authorized to investigate this target. "
        "Requests with authorized=False are rejected before anything is queued.",
    )


class InvestigationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str
    target_type: TargetType
    status: InvestigationStatus = InvestigationStatus.queued
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    progress: dict[str, str] = Field(default_factory=dict)
    error: str | None = None


class InvestigationResult(BaseModel):
    investigation_id: str
    threat_profile: dict | None = None
    graph: dict | None = None

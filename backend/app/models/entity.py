"""Shared schema produced by the normalization layer (week 3) and consumed by
both the LangChain synthesis chain (week 4) and the D3 graph in the React
dashboard (week 6). Keep this the single source of truth for shape."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

EntityType = Literal["domain", "ip", "email", "person", "org", "repo", "cve"]
RelationshipType = Literal["resolves_to", "employee_of", "leaked_in", "hosts", "owns", "mentions"]


class RawFinding(BaseModel):
    source: str  # e.g. "shodan", "github", "crt.sh", "hibp"
    query: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload: dict[str, Any]
    entity_refs: list[str] = Field(default_factory=list)


class Entity(BaseModel):
    id: str
    type: EntityType
    value: str
    confidence: float = 1.0
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    sources: list[str] = Field(default_factory=list)


class Relationship(BaseModel):
    source_entity_id: str
    target_entity_id: str
    type: RelationshipType
    confidence: float = 1.0


class ThreatProfile(BaseModel):
    target: str
    summary: str
    risk_indicators: list[str] = Field(default_factory=list)
    entities: list[Entity] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    model_version: str = "unset"

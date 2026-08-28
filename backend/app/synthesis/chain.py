"""LangChain synthesis chain (week 4). Two stages:
  1. extraction  — tag each RawFinding with entity type + relevance
  2. synthesis    — compose the ThreatProfile from tagged findings, with
                     each risk_indicator citing back to a RawFinding
Force structured output via a Pydantic output parser / tool-calling so the
API and PDF export never have to re-parse prose."""

from ..models.entity import ThreatProfile


async def synthesize_threat_profile(graph: dict) -> ThreatProfile:
    raise NotImplementedError("Implement in week 4")

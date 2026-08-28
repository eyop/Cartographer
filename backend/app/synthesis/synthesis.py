"""Synthesis schema + prompts (week 4, synthesis stage 2).

Composes a ThreatProfile summary and risk indicators from the normalized
graph and extracted signals.  Uses OpenAI structured output via Pydantic parse.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

SYNTHESIS_SYSTEM_PROMPT = (
    "You are an OSINT threat intelligence analyst. Given a target and a graph "
    "of entities and relationships gathered from multiple public sources, "
    "compose a concise (2-4 paragraph) executive summary of the security "
    "posture and a list of risk indicators. Each risk indicator should cite "
    "which source and entity it derives from. Never fabricate findings — "
    "only summarize what the data shows. If no risks are apparent, state that "
    "explicitly."
)

SYNTHESIS_HUMAN_PROMPT = (
    "Target: {target}\n\n"
    "{entity_count} entities across {source_count} sources, "
    "{relationship_count} relationships.\n\n"
    "Entities:\n{entities_str}\n\n"
    "Relationships:\n{relationships_str}\n\n"
    "Raw findings from {finding_count} sources: {sources_str}\n\n"
    "Extracted risk signals:\n{signals_str}\n\n"
    "Compose an executive summary and list 3-8 risk indicators with citations."
)


class SynthesisResult(BaseModel):
    summary: str = Field(
        ...,
        description="Executive summary of the target's OSINT security posture (2-4 paragraphs)",
    )
    risk_indicators: list[str] = Field(
        default_factory=list,
        description="Risk indicators, each citing its source and entity",
    )

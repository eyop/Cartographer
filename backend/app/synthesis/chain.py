"""LangChain/OpenAI synthesis chain (week 4). Two stages:
1. extraction  — tag each RawFinding with entity types + risk signals
2. synthesis   — compose the ThreatProfile summary + risk_indicators

Structured output via OpenAI's Pydantic parse API — frontend and PDF export
both need a schema, not prose to re-parse.

Falls back to a graph-derived summary when no OPENAI_API_KEY is set, so the
pipeline works end-to-end in CI without an LLM key.
"""

from __future__ import annotations

import json
from datetime import datetime

try:
    from openai import AsyncOpenAI
except ImportError:
    AsyncOpenAI = None  # type: ignore[assignment, misc]

from ..config import settings
from ..models.entity import Entity, RawFinding, Relationship, ThreatProfile
from .extraction import (
    EXTRACTION_HUMAN_PROMPT,
    EXTRACTION_SYSTEM_PROMPT,
    ExtractionResult,
)
from .synthesis import (
    SYNTHESIS_HUMAN_PROMPT,
    SYNTHESIS_SYSTEM_PROMPT,
    SynthesisResult,
)

MODEL_VERSION = "gpt-4o-mini-v1"


class ThreatSynthesisChain:
    """Orchestrates the two-stage LLM pipeline."""

    def __init__(self) -> None:
        self._client: AsyncOpenAI | None = None
        if settings.openai_api_key and AsyncOpenAI is not None:
            self._client = AsyncOpenAI(api_key=settings.openai_api_key)

    async def synthesize(
        self,
        target: str,
        graph: dict,
        raw_findings: list[RawFinding],
    ) -> ThreatProfile:
        """Run extraction then synthesis, returning a structured ThreatProfile."""
        entities = [Entity(**e) for e in graph.get("entities", [])]
        relationships = [Relationship(**r) for r in graph.get("relationships", [])]

        if self._client is None:
            return self._fallback(target, graph, raw_findings, entities, relationships)

        # Stage 1 — extraction (per finding)
        all_signals: list[str] = []
        for finding in raw_findings:
            result = await self._extract(finding)
            if result:
                all_signals.extend(result.risk_signals)

        # Stage 2 — synthesis
        summary, indicators = await self._synthesize(
            target, graph, all_signals, raw_findings,
        )

        return ThreatProfile(
            target=target,
            summary=summary,
            risk_indicators=indicators,
            entities=entities,
            relationships=relationships,
            generated_at=datetime.utcnow(),
            model_version=MODEL_VERSION,
        )

    async def _extract(self, finding: RawFinding) -> ExtractionResult | None:
        messages = [
            {"role": "system", "content": EXTRACTION_SYSTEM_PROMPT},
            {"role": "user", "content": EXTRACTION_HUMAN_PROMPT.format(
                source=finding.source,
                query=finding.query,
                payload_str=json.dumps(finding.payload, default=str)[:4000],
            )},
        ]
        try:
            resp = await self._client.beta.chat.completions.parse(
                model=settings.llm_model,
                messages=messages,
                response_format=ExtractionResult,
            )
            return resp.choices[0].message.parsed
        except Exception:
            return None

    async def _synthesize(
        self,
        target: str,
        graph: dict,
        signals: list[str],
        raw_findings: list[RawFinding],
    ) -> tuple[str, list[str]]:
        src_count = len(set(f.source for f in raw_findings))
        src_str = ", ".join(sorted(set(f.source for f in raw_findings))) or "(none)"

        ent_lines = [
            f"  - {e['type']}: {e['value']} (conf={e['confidence']:.2f}, sources={e['sources']})"
            for e in graph.get("entities", [])
        ] or ["  (none)"]
        rel_lines = [
            f"  - {r['source_entity_id']} {r['type']} {r['target_entity_id']} (conf={r['confidence']:.2f})"
            for r in graph.get("relationships", [])
        ] or ["  (none)"]
        sig_lines = [f"  - {s}" for s in signals] or ["  (none)"]

        messages = [
            {"role": "system", "content": SYNTHESIS_SYSTEM_PROMPT},
            {"role": "user", "content": SYNTHESIS_HUMAN_PROMPT.format(
                target=target,
                entity_count=len(graph.get("entities", [])),
                source_count=src_count,
                relationship_count=len(graph.get("relationships", [])),
                entities_str="\n".join(ent_lines),
                relationships_str="\n".join(rel_lines),
                finding_count=len(raw_findings),
                sources_str=src_str,
                signals_str="\n".join(sig_lines),
            )},
        ]
        try:
            resp = await self._client.beta.chat.completions.parse(
                model=settings.llm_model,
                messages=messages,
                response_format=SynthesisResult,
            )
            parsed = resp.choices[0].message.parsed
            return parsed.summary, parsed.risk_indicators
        except Exception:
            return self._fallback_summary(target, graph, signals), []

    def _fallback(
        self,
        target: str,
        graph: dict,
        raw_findings: list[RawFinding],
        entities: list[Entity],
        relationships: list[Relationship],
    ) -> ThreatProfile:
        summary = self._fallback_summary(target, graph, [])
        indicators: list[str] = []
        for rel in relationships:
            if rel.type == "leaked_in":
                tgt = _lookup_rel_target(rel, entities)
                indicators.append(
                    f"Email address associated with {tgt} "
                    f"appeared in a data breach (source: hibp)"
                )
            elif rel.type == "resolves_to":
                indicators.append(
                    f"Domain resolves to an external IP address (source: dns/shodan)"
                )
        if not indicators:
            indicators.append(
                "Passive reconnaissance completed. No significant risk "
                "indicators identified without additional intelligence sources."
            )
        return ThreatProfile(
            target=target,
            summary=summary,
            risk_indicators=indicators,
            entities=entities,
            relationships=relationships,
            generated_at=datetime.utcnow(),
            model_version="fallback-v1",
        )

    @staticmethod
    def _fallback_summary(target: str, graph: dict, signals: list[str]) -> str:
        ents = graph.get("entities", [])
        rels = graph.get("relationships", [])
        sources: set[str] = set()
        for e in ents:
            sources.update(e.get("sources", []))
        parts = [
            f"OSINT investigation for '{target}'.",
            f"Collected {len(ents)} entities and {len(rels)} relationships "
            f"from {len(sources)} source(s): {', '.join(sorted(sources)) or 'none'}.",
        ]
        if any(r.get("type") == "leaked_in" for r in rels):
            parts.append("Warning: associated accounts appear in data breach results.")
        if signals:
            parts.append(f"Detected {len(signals)} risk signal(s).")
        return " ".join(parts)


def _lookup_rel_target(rel: Relationship, entities: list[Entity]) -> str:
    for e in entities:
        if e.id == rel.target_entity_id:
            return e.value
    return rel.target_entity_id


async def synthesize_threat_profile(
    target: str,
    graph: dict,
    raw_findings: list[RawFinding],
) -> ThreatProfile:
    """Module-level entry point expected by workers/tasks.py."""
    chain = ThreatSynthesisChain()
    return await chain.synthesize(target, graph, raw_findings)

"""Extraction schema + prompts (week 4, synthesis stage 1).

For each RawFinding, the LLM tags entity types and risk signals present in
the payload.  Uses OpenAI structured output via Pydantic parse.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

EXTRACTION_SYSTEM_PROMPT = (
    "You are an OSINT analyst assistant. Given a raw finding from a specific "
    "intelligence source, identify all entities (domains, IP addresses, "
    "emails, organizations, repositories, CVE IDs) and risk signals (data "
    "breaches, exposed services, vulnerabilities, malicious indicators) "
    "present in the payload. Return structured JSON. Be conservative — only "
    "tag things you are confident about from the data."
)

EXTRACTION_HUMAN_PROMPT = (
    "Source: {source}\n"
    "Query: {query}\n\n"
    "Raw payload (truncated to 4000 chars):\n"
    "{payload_str}\n\n"
    "Extract all entities and risk signals you can identify."
)


class ExtractionResult(BaseModel):
    entity_values: list[str] = Field(
        default_factory=list,
        description="Entity values found in the payload (domains, IPs, emails, orgs, repos, CVEs)",
    )
    risk_signals: list[str] = Field(
        default_factory=list,
        description="Risk signals: breaches, exposed ports, vulnerabilities, malicious activity",
    )

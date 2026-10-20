"""Normalization layer — converts RawFinding[] into a unified
{entities, relationships} graph (week 3).

This is the single transformation between per-source collectors and downstream
consumers (LangChain synthesis + D3 graph).  Each source gets a dedicated
normalizer that understands its payload schema; the dispatcher normalize()
routes by finding.source.

Entity IDs are deterministic (ent:{type}:{md5(value)[:12]}) so the same
real-world entity from multiple sources is deduplicated into one node.
"""

from __future__ import annotations

import hashlib
import re
from typing import Callable

from ..models.entity import (
    Entity,
    EntityType,
    Relationship,
    RelationshipType,
    RawFinding,
)


def _entity_id(entity_type: str, value: str) -> str:
    """Deterministic entity id for deduplication + relationship references."""
    digest = hashlib.md5(value.encode()).hexdigest()[:12]
    return f"ent:{entity_type}:{digest}"


class GraphBuilder:
    """Accumulates entities and relationships with automatic deduplication."""

    def __init__(self) -> None:
        self._entities: dict[str, Entity] = {}
        self._relationships: dict[str, Relationship] = {}

    def add_entity(
        self,
        entity_type: EntityType,
        value: str,
        confidence: float,
        sources: list[str],
    ) -> str:
        """Add (or merge) an entity. Returns its deterministic id."""
        eid = _entity_id(entity_type, value)
        if eid in self._entities:
            existing = self._entities[eid]
            existing.confidence = max(existing.confidence, confidence)
            for s in sources:
                if s not in existing.sources:
                    existing.sources.append(s)
        else:
            self._entities[eid] = Entity(
                id=eid,
                type=entity_type,
                value=value,
                confidence=confidence,
                sources=list(sources),
            )
        return eid

    def add_relationship(
        self,
        src_type: EntityType,
        src_value: str,
        tgt_type: EntityType,
        tgt_value: str,
        rel_type: RelationshipType,
        confidence: float,
        sources: list[str],
    ) -> None:
        """Add a relationship, ensuring both endpoint entities exist."""
        src_id = self.add_entity(src_type, src_value, confidence, sources)
        tgt_id = self.add_entity(tgt_type, tgt_value, confidence, sources)
        key = f"{src_id}->{tgt_id}:{rel_type}"
        if key not in self._relationships:
            self._relationships[key] = Relationship(
                source_entity_id=src_id,
                target_entity_id=tgt_id,
                type=rel_type,
                confidence=confidence,
            )

    def build(self) -> dict:
        """Serialize to plain dicts (JSON-serializable for Redis + API)."""
        return {
            "entities": [e.model_dump() for e in self._entities.values()],
            "relationships": [r.model_dump() for r in self._relationships.values()],
        }


_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


# ---------------------------------------------------------------------------
# Per-source normalizers
# ---------------------------------------------------------------------------


def _normalize_dns(builder: GraphBuilder, finding: RawFinding) -> None:
    """DNS resolution results — Cloudflare DoH A-record answers."""
    payload = finding.payload
    query = finding.query.rstrip(".").lower()
    builder.add_entity("domain", query, 1.0, [finding.source])

    for ans in payload.get("Answer", []):
        if ans.get("type") != 1:  # A record only
            continue

        ip = ans.get("data")
        name = (ans.get("name") or "").rstrip(".").lower()
        if not ip:
            continue

        if name and name != query:
            continue

        builder.add_entity("ip", ip, 1.0, [finding.source])
        builder.add_relationship(
            "domain", query, "ip", ip,
            "resolves_to", 0.95, [finding.source],
        )


def _normalize_crtsh(builder: GraphBuilder, finding: RawFinding) -> None:
    """Certificate Transparency log results — crt.sh."""
    payload = finding.payload
    query = finding.query
    builder.add_entity("domain", query, 1.0, [finding.source])

    for cert in payload.get("certificates", []):
        # name_value may contain multiple SANs separated by newlines
        for name in (cert.get("name_value") or "").split("\n"):
            name = name.strip()
            if not name:
                continue
            clean = name.lstrip("*.")
            builder.add_entity("domain", clean, 0.9, [finding.source])
            builder.add_relationship(
                "domain", query, "domain", clean,
                "hosts", 0.7, [finding.source],
            )

        # issuer_name like "C=US, O=Let's Encrypt, CN=R3"
        issuer = cert.get("issuer_name", "")
        org_match = re.search(r"O=([^,]+)", issuer)
        if org_match:
            org = org_match.group(1).strip()
            builder.add_entity("org", org, 0.8, [finding.source])
            builder.add_relationship(
                "org", org, "domain", query,
                "owns", 0.6, [finding.source],
            )


def _normalize_github(builder: GraphBuilder, finding: RawFinding) -> None:
    """GitHub code-search results — repos mentioning the target."""
    payload = finding.payload
    query = finding.query
    is_email = "@" in query
    builder.add_entity("email" if is_email else "domain", query, 1.0, [finding.source])

    for item in payload.get("items", []):
        repo = item.get("repository", {})
        full_name = repo.get("full_name", "")
        if not full_name:
            continue
        org_name = full_name.split("/")[0]
        builder.add_entity("org", org_name, 0.9, [finding.source])
        builder.add_entity("repo", full_name, 0.9, [finding.source])
        builder.add_relationship(
            "org", org_name, "repo", full_name,
            "owns", 0.8, [finding.source],
        )
        # The repo mentions the target
        builder.add_relationship(
            "repo", full_name,
            "email" if is_email else "domain", query,
            "mentions", 0.5, [finding.source],
        )


def _normalize_shodan(builder: GraphBuilder, finding: RawFinding) -> None:
    """Shodan host search — indexed internet-exposed hosts."""
    payload = finding.payload

    for match in payload.get("matches", []):
        ip_str = match.get("ip_str")
        org = match.get("org", "")
        hostnames = match.get("hostnames", [])

        if not ip_str:
            continue
        builder.add_entity("ip", ip_str, 0.9, [finding.source])
        if org:
            builder.add_entity("org", org, 0.8, [finding.source])
            builder.add_relationship(
                "org", org, "ip", ip_str, "hosts", 0.7, [finding.source],
            )
        for hostname in hostnames:
            builder.add_entity("domain", hostname, 0.8, [finding.source])
            builder.add_relationship(
                "domain", hostname, "ip", ip_str,
                "resolves_to", 0.9, [finding.source],
            )


def _normalize_virustotal(builder: GraphBuilder, finding: RawFinding) -> None:
    """VirusTotal v3 domain report."""
    payload = finding.payload
    query = finding.query
    builder.add_entity("domain", query, 1.0, [finding.source])

    attrs = payload.get("data", {}).get("attributes", {})

    # Resolutions: IPs the domain resolves to
    for res in attrs.get("resolutions", []):
        ip = res.get("ip_address")
        if ip:
            builder.add_entity("ip", ip, 0.8, [finding.source])
            builder.add_relationship(
                "domain", query, "ip", ip,
                "resolves_to", 0.8, [finding.source],
            )

    # Subdomains
    for sub in attrs.get("subdomains", []):
        builder.add_entity("domain", sub, 0.7, [finding.source])
        builder.add_relationship(
            "domain", query, "domain", sub,
            "hosts", 0.7, [finding.source],
        )

    # Reputational enrichment from whois text
    whois = attrs.get("whois", "")
    for ip in _IP_RE.findall(whois)[:5]:
        builder.add_entity("ip", ip, 0.5, [finding.source])
        builder.add_relationship(
            "domain", query, "ip", ip,
            "resolves_to", 0.5, [finding.source],
        )


def _normalize_hibp(builder: GraphBuilder, finding: RawFinding) -> None:
    """HaveIBeenPwned breach results — leaked-account indicators."""
    payload = finding.payload
    query = finding.query  # email address
    builder.add_entity("email", query, 1.0, [finding.source])

    for breach in payload.get("breaches", []):
        breach_domain = breach.get("Domain", "")
        breach_name = breach.get("Name", "")
        is_verified = breach.get("IsVerified", False)
        data_classes = breach.get("DataClasses", [])
        confidence = 0.95 if is_verified else 0.7

        if breach_domain:
            builder.add_entity("domain", breach_domain, 0.9, [finding.source])
            builder.add_relationship(
                "email", query, "domain", breach_domain,
                "leaked_in", confidence, [finding.source],
            )

        if breach_name:
            builder.add_entity("org", breach_name, 0.8, [finding.source])
            builder.add_relationship(
                "email", query, "org", breach_name,
                "leaked_in", confidence, [finding.source],
            )

        for dc in data_classes:
            builder.add_entity(
                "org", f"breach-data:{dc}", 0.6, [finding.source],
            )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

NORMALIZERS: dict[str, Callable[[GraphBuilder, RawFinding], None]] = {
    "dns": _normalize_dns,
    "crtsh": _normalize_crtsh,
    "github": _normalize_github,
    "shodan": _normalize_shodan,
    "virustotal": _normalize_virustotal,
    "hibp": _normalize_hibp,
}


def normalize(raw_findings: list[RawFinding]) -> dict:
    """Convert a list of RawFinding objects into a unified graph dict.

    Returns {"entities": [...], "relationships": [...]} with deterministic
    ids so downstream consumers (LLM + D3) share the same schema.
    """
    builder = GraphBuilder()
    for finding in raw_findings:
        handler = NORMALIZERS.get(finding.source)
        if handler:
            handler(builder, finding)
    return builder.build()

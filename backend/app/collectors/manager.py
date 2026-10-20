"""Collector registry and target-type routing (week 2).

``CollectorManager`` instantiates every collector once (with shared redis +
http clients + API keys from config) and exposes ``get_collectors`` which
returns only the collectors that are both relevant to the target_type *and*
report they can handle the specific target.
"""

from __future__ import annotations

import httpx
from redis.asyncio import Redis

from ..config import settings
from .base import BaseCollector
from .crtsh import CrtShCollector
from .dns import DNSCollector
from .github import GitHubCollector
from .hibp import HIBPCollector
from .shodan import ShodanCollector
from .virustotal import VirusTotalCollector

# Routing matrix: which sources to query for each target type.
# Order matters for progress reporting — most informative first.
ROUTING: dict[str, list[str]] = {
    "domain":  ["dns", "crtsh", "shodan", "virustotal"],
    "email":   ["hibp", "virustotal"],
    "company": ["github", "crtsh", "shodan", "virustotal"],
    "person":  ["github", "hibp"],
}


class CollectorManager:
    """Instantiate all collectors and route by target type."""

    def __init__(self, redis: Redis, http_client: httpx.AsyncClient):
        self._collectors: dict[str, BaseCollector] = {
            "dns": DNSCollector(redis, http_client),
            "crtsh": CrtShCollector(redis, http_client),
            "github": GitHubCollector(redis, http_client, settings.github_token),
            "shodan": ShodanCollector(redis, http_client, settings.shodan_api_key),
            "virustotal": VirusTotalCollector(redis, http_client, settings.virustotal_api_key),
            "hibp": HIBPCollector(redis, http_client, settings.hibp_api_key),
        }

    def get_collectors(self, target: str, target_type: str) -> list[BaseCollector]:
        """Return all collectors for *target_type* that can handle *target*."""
        names = ROUTING.get(target_type, [])
        result = []
        for name in names:
            collector = self._collectors[name]
            if not collector.can_handle(target, target_type):
                continue

            if name in {"github", "shodan", "virustotal", "hibp"}:
                # These collectors are either API-key gated or should be excluded in a no-key environment.
                configured = {
                    "github": bool(settings.github_token),
                    "shodan": bool(settings.shodan_api_key),
                    "virustotal": bool(settings.virustotal_api_key),
                    "hibp": bool(settings.hibp_api_key),
                }.get(name, True)
                if not configured:
                    continue

            result.append(collector)
        return result

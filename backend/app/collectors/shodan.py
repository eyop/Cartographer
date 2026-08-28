"""Shodan collector (week 2).

Queries the Shodan API for host information associated with a domain or IP.
Uses Shodan's host search endpoint to look up `hostname:<domain>` queries.

Requires ``SHODAN_API_KEY``.  Free tier: 1 req / 5 s.

API docs: https://developer.shodan.io/
"""

from __future__ import annotations

import httpx

from .base_http import BaseHttpCollector


class ShodanCollector(BaseHttpCollector):
    source_name = "shodan"

    def __init__(self, redis, http_client, shodan_api_key: str):
        super().__init__(redis, http_client)
        self.shodan_api_key = shodan_api_key

    def can_handle(self, target: str, target_type: str) -> bool:
        # Shodan host search is meaningful for domains and IPs.
        return target_type in ("domain", "company")

    async def _fetch_raw(self, target: str) -> dict | None:
        if not self.shodan_api_key:
            return None

        params = {"key": self.shodan_api_key, "query": f"hostname:{target}"}
        resp = await self.http.get(
            "https://api.shodan.io/shodan/host/search",
            params=params,
        )
        resp.raise_for_status()
        return resp.json()

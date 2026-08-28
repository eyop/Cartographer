"""DNS collector — queries Cloudflare's DNS-over-HTTPS API (week 2).

No API key required.  Falls back to recording A-record resolution for the
target domain.  Uses Cloudflare's DoH endpoint which returns standard
`application/dns-json` responses.

API docs: https://developers.cloudflare.com/1.1.1.1/dns-over-https/
"""

from __future__ import annotations

import httpx

from .base_http import BaseHttpCollector


class DNSCollector(BaseHttpCollector):
    source_name = "dns"

    async def _fetch_raw(self, target: str) -> dict | None:
        """Query Cloudflare DoH for A + AAAA records of *target*."""
        headers = {"accept": "application/dns-json"}
        params = {"name": target, "type": "A"}
        resp = await self.http.get(
            "https://dns.cloudflare.com/dns-query",
            params=params,
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()

    def can_handle(self, target: str, target_type: str) -> bool:
        # DNS resolution makes sense for domains (and companies that are domains).
        return target_type == "domain"

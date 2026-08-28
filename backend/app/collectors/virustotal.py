"""VirusTotal v3 collector (week 2).

Queries the VirusTotal API for domain or IP intelligence.  Returns metadata,
categories, last-analysis stats, and WHOIS-like info.

Requires ``VIRUSTOTAL_API_KEY``.  Free tier: 4 req/min.

API docs: https://developers.virustotal.com/reference
"""

from __future__ import annotations

import httpx

from .base_http import BaseHttpCollector


class VirusTotalCollector(BaseHttpCollector):
    source_name = "virustotal"

    def __init__(self, redis, http_client, virustotal_api_key: str):
        super().__init__(redis, http_client)
        self.vt_api_key = virustotal_api_key

    def can_handle(self, target: str, target_type: str) -> bool:
        return target_type in ("domain", "company")

    async def _fetch_raw(self, target: str) -> dict | None:
        if not self.vt_api_key:
            return None

        headers = {"x-apikey": self.vt_api_key}
        # Try domain endpoint first; VT v3 uses /domains/{domain}
        url = f"https://www.virustotal.com/api/v3/domains/{target}"
        resp = await self.http.get(url, headers=headers)

        if resp.status_code == 404:
            # Maybe it's an IP address instead
            url_ip = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            resp = await self.http.get(url_ip, headers=headers)

        if resp.status_code == 404:
            return None

        resp.raise_for_status()
        return resp.json()

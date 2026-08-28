"""crt.sh collector — Certificate Transparency log search (week 2).

No API key required.  Queries the public crt.sh search endpoint which
returns JSON — one record per certificate that references the queried
domain (including wildcard and SAN entries).

Endpoint: https://crt.sh/?q=<domain>&output=json
"""

from __future__ import annotations

import urllib.parse

import httpx

from .base_http import BaseHttpCollector


class CrtShCollector(BaseHttpCollector):
    source_name = "crtsh"

    async def _fetch_raw(self, target: str) -> dict | None:
        """Query crt.sh for certificates matching *target*.

        Returns the raw JSON array (wrapped in a dict for cache uniformity).
        """
        url = "https://crt.sh/"
        params = {"q": target, "output": "json"}
        resp = await self.http.get(url, params=params)
        resp.raise_for_status()
        data = resp.json()
        # crt.sh returns a bare JSON array; wrap for cache consistency.
        if isinstance(data, list):
            return {"certificates": data}
        return data

    def can_handle(self, target: str, target_type: str) -> bool:
        return target_type in ("domain", "company")

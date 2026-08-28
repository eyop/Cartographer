"""HaveIBeenPwned v3 collector (week 2).

Queries the HIBP API for breached accounts associated with an email address.
Each breach result includes the breach name, title, compromised data classes,
and whether the breach was verified.

Requires ``HIBP_API_KEY``.  Rate limit: 1 req / 1.5 s.
Note: API key must be on the paid v3 plan to query by email.

API docs: https://haveibeenpwned.com/API/v3
"""

from __future__ import annotations

import httpx

from .base_http import BaseHttpCollector


class HIBPCollector(BaseHttpCollector):
    source_name = "hibp"

    def __init__(self, redis, http_client, hibp_api_key: str):
        super().__init__(redis, http_client)
        self.hibp_api_key = hibp_api_key

    def can_handle(self, target: str, target_type: str) -> bool:
        # HIBP breach lookup is meaningful for email targets.
        return target_type == "email"

    async def _fetch_raw(self, target: str) -> dict | None:
        if not self.hibp_api_key:
            return None

        headers = {
            "hibp-api-key": self.hibp_api_key,
            "user-agent": "Cartographer-OSINT",
        }
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}"
        # HIBP returns 404 when no breaches are found — treat as empty.
        resp = await self.http.get(url, headers=headers)
        if resp.status_code == 404:
            return {"breaches": []}
        resp.raise_for_status()
        # HIBP returns a JSON array of breach objects
        data = resp.json()
        if isinstance(data, list):
            return {"breaches": data}
        return data

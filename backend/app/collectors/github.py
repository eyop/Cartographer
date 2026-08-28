"""GitHub Search collector (week 2).

Uses the GitHub Code Search API to find repositories, code, or users that
reference the target.  Returns RawFinding objects with the raw search results.

Requires ``GITHUB_TOKEN`` env var (configured in settings).  Authenticated
search is rate-limited to 30 req/min.

API docs: https://docs.github.com/en/rest/search
"""

from __future__ import annotations

import httpx

from .base_http import BaseHttpCollector


class GitHubCollector(BaseHttpCollector):
    source_name = "github"

    def __init__(self, redis, http_client, github_token: str):
        super().__init__(redis, http_client)
        self.github_token = github_token

    def can_handle(self, target: str, target_type: str) -> bool:
        # GitHub search works for any free-text target type.
        return True

    async def _fetch_raw(self, target: str) -> dict | None:
        if not self.github_token:
            return None

        headers = {
            "Authorization": f"Bearer {self.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Cartographer-OSINT",
        }

        # Search code for references to the target.
        params = {"q": target, "per_page": 30}
        resp = await self.http.get(
            "https://api.github.com/search/code",
            params=params,
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()

"""
github_connector.py
--------------------
Searches public GitHub repositories for candidate resources.

Works WITHOUT a token (unauthenticated), just at a much lower rate limit
(~10 requests/min for search endpoints vs ~30/min authenticated, and
~60/hour vs ~5,000/hour for general API calls). Pass GITHUB_TOKEN via
environment variable to raise those limits.

GitHub Search API docs: https://docs.github.com/en/rest/search
"""

import os
from typing import Optional

import httpx

GITHUB_API_BASE = "https://api.github.com"


class GitHubConnector:
    """Implements the common connector interface: search(requirement) -> List[Candidate dict]."""

    name = "github"

    def __init__(self, token: Optional[str] = None, timeout: float = 10.0):
        # Falls back to env var if not passed explicitly.
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.timeout = timeout

    def _headers(self) -> dict:
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _build_query(self, requirement: dict) -> str:
        """
        Builds a GitHub search query string from a parsed Requirement.
        Combines topics as free-text terms; GitHub search ranks on relevance.
        """
        topics = requirement.get("topics", [])
        resource_types = requirement.get("resource_types", [])

        terms = list(topics)
        # "dataset" as a resource type is a useful search keyword on GitHub too.
        if "dataset" in [t.lower() for t in resource_types]:
            terms.append("dataset")

        query = " ".join(terms).strip()
        return query if query else "dataset"

    def _get_latest_commit_sha(self, client: httpx.Client, full_name: str, default_branch: str) -> str:
        """
        Best-effort fetch of the latest commit SHA on the default branch.
        Falls back to the branch name itself if this call fails (e.g., rate limit),
        so the connector never crashes the whole search just for this detail.
        """
        try:
            resp = client.get(
                f"{GITHUB_API_BASE}/repos/{full_name}/commits/{default_branch}",
                headers=self._headers(),
                params={"per_page": 1},
            )
            if resp.status_code == 200:
                data = resp.json()
                sha = data.get("sha")
                if sha:
                    return sha
        except httpx.HTTPError:
            pass
        return default_branch  # fallback: branch name as a soft "version" marker

    def _score(self, item: dict, requirement: dict) -> tuple[float, dict]:
        """
        Simple, explainable scoring (NFR4). Not a legal/safety claim — just ranking.
        """
        breakdown = {}

        # Topical relevance: how many requirement topics appear in name/description.
        # Normalize hyphens/underscores to spaces since repo names/slugs commonly
        # use them instead of spaces (e.g. "it-support-tickets").
        name = item.get("name", "") or ""
        description = item.get("description", "") or ""
        text = f"{name} {description}".lower().replace("-", " ").replace("_", " ")
        topics = [t.lower() for t in requirement.get("topics", [])]
        matches = sum(1 for t in topics if t in text)
        relevance = min(matches / max(len(topics), 1), 1.0)
        breakdown["topical_relevance"] = round(relevance, 2)

        # License evidence: does GitHub report a detected license?
        has_license = bool(item.get("license"))
        breakdown["license_evidence_present"] = 1.0 if has_license else 0.0

        # Popularity as a weak signal only (capped so huge repos don't dominate purely on stars).
        stars = item.get("stargazers_count", 0) or 0
        popularity = min(stars / 1000, 1.0)
        breakdown["popularity_signal"] = round(popularity, 2)

        # Weighted combination — weights chosen to prioritize relevance and license over popularity.
        total = (0.6 * relevance) + (0.25 * breakdown["license_evidence_present"]) + (0.15 * popularity)
        return round(total, 3), breakdown

    def search(self, requirement: dict, max_results: int = 5) -> list[dict]:
        """
        Returns a list of dicts shaped to match the `Candidate` fields expected
        by `repository.create_candidate` (minus id/requirement_id/discovered_at,
        which the caller fills in).
        """
        query = self._build_query(requirement)
        candidates: list[dict] = []

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(
                    f"{GITHUB_API_BASE}/search/repositories",
                    headers=self._headers(),
                    params={"q": query, "per_page": max_results, "sort": "stars", "order": "desc"},
                )

                if resp.status_code == 403:
                    # Rate-limited or blocked — degrade gracefully (NFR5), don't raise.
                    return []
                if resp.status_code != 200:
                    return []

                data = resp.json()
                items = data.get("items", [])[:max_results]

                for item in items:
                    full_name = item.get("full_name")
                    default_branch = item.get("default_branch", "main")
                    version = self._get_latest_commit_sha(client, full_name, default_branch)

                    license_info = item.get("license") or {}
                    score, breakdown = self._score(item, requirement)

                    candidates.append({
                        "provider": "github",
                        "source_url": item.get("html_url"),
                        "version_or_commit": version,
                        "title": full_name,
                        "description": item.get("description") or "",
                        "format": "repository",
                        "size_bytes": (item.get("size") or 0) * 1024,  # GitHub reports size in KB
                        "license": license_info.get("spdx_id"),
                        "license_evidence": (
                            f"GitHub-detected license: {license_info.get('name')}"
                            if license_info.get("name") else None
                        ),
                        "relevance_score": score,
                        "score_breakdown": breakdown,
                    })

        except httpx.HTTPError:
            # Network/timeout errors also degrade gracefully rather than crashing the pipeline.
            return []

        return candidates


if __name__ == "__main__":
    # Quick manual smoke test — run with: python -m app.connectors.github_connector
    connector = GitHubConnector()
    fake_requirement = {
        "topics": ["IT support tickets", "incident resolution"],
        "resource_types": ["dataset"],
    }
    results = connector.search(fake_requirement, max_results=3)
    for r in results:
        print(r["title"], "-", r["relevance_score"], "-", r["source_url"])

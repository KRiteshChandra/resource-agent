"""
huggingface_connector.py
-------------------------
Searches public Hugging Face Hub datasets for candidate resources.

Works WITHOUT a token for public dataset search/listing. Pass HF_TOKEN via
environment variable only if you need access to gated/private datasets or
want higher rate limits.

Hugging Face Hub API docs: https://huggingface.co/docs/hub/api
Datasets search endpoint:  https://huggingface.co/api/datasets
"""

import os
from typing import Optional

import httpx

HF_API_BASE = "https://huggingface.co/api"


class HuggingFaceConnector:
    """Implements the common connector interface: search(requirement) -> List[Candidate dict]."""

    name = "huggingface"

    def __init__(self, token: Optional[str] = None, timeout: float = 10.0):
        self.token = token or os.getenv("HF_TOKEN")
        self.timeout = timeout

    def _headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _build_search_term(self, requirement: dict) -> str:
        """
        Hugging Face dataset search is a simple free-text `search` param matched
        against dataset id/tags/description. Join topics into one search string.
        """
        topics = requirement.get("topics", [])
        term = " ".join(topics).strip()
        return term if term else "dataset"

    def _get_dataset_detail(self, client: httpx.Client, dataset_id: str) -> Optional[dict]:
        """
        Fetches full dataset detail (includes `sha` of the latest revision on
        the main branch, which we use as `version_or_commit`).
        """
        try:
            resp = client.get(f"{HF_API_BASE}/datasets/{dataset_id}", headers=self._headers())
            if resp.status_code == 200:
                return resp.json()
        except httpx.HTTPError:
            pass
        return None

    def _score(self, item: dict, requirement: dict) -> tuple[float, dict]:
        """Simple, explainable scoring — ranking aid only (same spirit as GitHub connector)."""
        breakdown = {}

        dataset_id = item.get("id", "") or ""
        tags = item.get("tags", []) or []
        # Dataset IDs/tags use hyphens/underscores instead of spaces (e.g.
        # "it-support-tickets"), so normalize both sides to spaces before
        # matching, otherwise multi-word topics never match real HF slugs.
        text = f"{dataset_id} {' '.join(tags)}".lower().replace("-", " ").replace("_", " ")

        topics = [t.lower() for t in requirement.get("topics", [])]
        matches = sum(1 for t in topics if t in text)
        relevance = min(matches / max(len(topics), 1), 1.0)
        breakdown["topical_relevance"] = round(relevance, 2)

        # License evidence: HF often exposes license as a tag like "license:mit"
        license_tag = next((t for t in tags if t.startswith("license:")), None)
        breakdown["license_evidence_present"] = 1.0 if license_tag else 0.0

        # Popularity as a weak signal only, capped.
        downloads = item.get("downloads", 0) or 0
        popularity = min(downloads / 10000, 1.0)
        breakdown["popularity_signal"] = round(popularity, 2)

        total = (0.6 * relevance) + (0.25 * breakdown["license_evidence_present"]) + (0.15 * popularity)
        return round(total, 3), breakdown, license_tag

    def search(self, requirement: dict, max_results: int = 5) -> list[dict]:
        """
        Returns a list of dicts shaped to match the `Candidate` fields expected
        by `repository.create_candidate` (minus id/requirement_id/discovered_at,
        which the caller fills in).
        """
        search_term = self._build_search_term(requirement)
        candidates: list[dict] = []

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(
                    f"{HF_API_BASE}/datasets",
                    headers=self._headers(),
                    params={"search": search_term, "limit": max_results, "sort": "downloads", "direction": -1},
                )

                if resp.status_code in (401, 403):
                    # Missing/invalid token or rate-limited — degrade gracefully (NFR5).
                    return []
                if resp.status_code != 200:
                    return []

                items = resp.json()[:max_results]

                for item in items:
                    dataset_id = item.get("id")
                    score, breakdown, license_tag = self._score(item, requirement)

                    # Try to get a precise revision sha; fall back to "main" if unavailable.
                    detail = self._get_dataset_detail(client, dataset_id)
                    version = (detail or {}).get("sha", "main")

                    size_bytes = None
                    if detail and "cardData" in detail:
                        # Size isn't always available via this endpoint; left as None when unknown
                        # rather than guessing (avoid fabricating data).
                        pass

                    candidates.append({
                        "provider": "huggingface",
                        "source_url": f"https://huggingface.co/datasets/{dataset_id}",
                        "version_or_commit": version,
                        "title": dataset_id,
                        "description": ", ".join(item.get("tags", [])[:5]) or "",
                        "format": "dataset",
                        "size_bytes": size_bytes,
                        "license": license_tag.replace("license:", "") if license_tag else None,
                        "license_evidence": (
                            f"Hugging Face tag: {license_tag}" if license_tag else None
                        ),
                        "relevance_score": score,
                        "score_breakdown": breakdown,
                    })

        except httpx.HTTPError:
            return []

        return candidates


if __name__ == "__main__":
    # Quick manual smoke test — run with: python -m app.connectors.huggingface_connector
    connector = HuggingFaceConnector()
    fake_requirement = {
        "topics": ["IT support tickets", "incident resolution"],
        "resource_types": ["dataset"],
    }
    results = connector.search(fake_requirement, max_results=3)
    for r in results:
        print(r["title"], "-", r["relevance_score"], "-", r["source_url"])

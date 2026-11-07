"""
routers/resources.py
---------------------
Implements:
    GET /requests/{requirement_id}/resources  - ranked candidate resources

First call for a requirement runs discovery (GitHub + Hugging Face + web stub),
ranks the results and stores them. Later calls return the stored list, so the
candidate IDs (and the versions locked at approval time) stay stable.
If discovery finds nothing (e.g. rate-limited or offline), nothing is stored,
so the next call simply tries again.

Approve / download endpoints are added in the next step.
"""

from fastapi import APIRouter, Depends, HTTPException

from app import repository as repo
from app.connectors.github_connector import GitHubConnector
from app.connectors.huggingface_connector import HuggingFaceConnector
from app.connectors.web_search_connector import WebSearchConnector
from app.models.schemas import Candidate
from app.services.discovery import discover

router = APIRouter(tags=["resources"])


def get_connectors() -> list:
    """Dependency so tests can swap in fake connectors."""
    return [GitHubConnector(), HuggingFaceConnector(), WebSearchConnector()]


@router.get("/requests/{requirement_id}/resources", response_model=list[Candidate])
def get_ranked_resources(requirement_id: str, connectors: list = Depends(get_connectors)):
    requirement = repo.get_requirement(requirement_id)
    if not requirement:
        raise HTTPException(status_code=404, detail="Requirement not found")

    existing = repo.list_candidates_for_requirement(requirement_id)
    if existing:
        return existing

    for cand in discover(requirement, connectors):
        repo.create_candidate(
            requirement_id=requirement_id,
            provider=cand["provider"],
            source_url=cand["source_url"],
            version_or_commit=cand["version_or_commit"],
            title=cand.get("title") or cand["source_url"],
            description=cand.get("description") or "",
            format=cand.get("format"),
            size_bytes=cand.get("size_bytes"),
            license=cand.get("license"),
            license_evidence=cand.get("license_evidence"),
            relevance_score=cand["relevance_score"],
            score_breakdown=cand["score_breakdown"],
        )
    return repo.list_candidates_for_requirement(requirement_id)

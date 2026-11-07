"""
routers/requirements.py
------------------------
Implements:
    POST /requests  - submit a natural-language resource request
    GET  /requests   - list past requests

Per api-spec.yaml. Uses the rule-based RequirementParser (Stage 2) and
persists the parsed Requirement via the repository layer.
"""

from fastapi import APIRouter, HTTPException

from app.models.schemas import Requirement, RequirementCreate
from app.repository import create_requirement, get_requirement, list_requirements
from app.services.requirement_parser import RequirementParser

router = APIRouter(tags=["requirements"])
parser = RequirementParser()


@router.post("/requests", response_model=Requirement, status_code=201)
def submit_request(payload: RequirementCreate):
    """
    Parses the user's natural-language request into a structured Requirement
    and persists it. This Requirement is what connectors (GitHub, Hugging
    Face) will later search against.
    """
    parsed = parser.parse(payload.raw_text)

    requirement = create_requirement(
        raw_text=payload.raw_text,
        resource_types=parsed["resource_types"],
        topics=parsed["topics"],
        preferred_formats=parsed["preferred_formats"],
        license_preference=parsed["license_preference"],
        max_size_mb=parsed["max_size_mb"],
    )
    return requirement


@router.get("/requests", response_model=list[Requirement])
def get_requests():
    """Returns all past requests, most recent first."""
    return list_requirements()


@router.get("/requests/{requirement_id}", response_model=Requirement)
def get_request(requirement_id: str):
    """Returns a single requirement by id, or 404 if not found."""
    requirement = get_requirement(requirement_id)
    if not requirement:
        raise HTTPException(status_code=404, detail="Requirement not found")
    return requirement

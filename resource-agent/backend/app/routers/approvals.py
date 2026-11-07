"""
routers/approvals.py
---------------------
Implements:
    POST /resources/{resource_id}/approve

Thin HTTP layer only. All rules live in services/approval_service.py.

Status codes (api-spec.yaml):
    200  approval created (or already active for this exact version)
    404  resource not found
    409  source changed since discovery - re-confirm with accept_changed_version=true
    503  could not verify the current version with the provider (fail closed)
"""

from fastapi import APIRouter, Depends, HTTPException

from app.models.schemas import Approval, ApprovalCreate
from app.services import approval_service
from app.services.version_resolver import VersionResolver

router = APIRouter(tags=["approvals"])


class ApproveRequest(ApprovalCreate):
    """ApprovalCreate (approved_by) plus an explicit opt-in for a changed version."""
    accept_changed_version: bool = False


def get_version_resolver() -> VersionResolver:
    """Dependency so tests can swap in a fake resolver."""
    return VersionResolver()


@router.post("/resources/{resource_id}/approve", response_model=Approval)
def approve_resource(resource_id: str, payload: ApproveRequest,
                     resolver: VersionResolver = Depends(get_version_resolver)):
    try:
        return approval_service.approve_candidate(
            candidate_id=resource_id,
            approved_by=payload.approved_by,
            resolver=resolver,
            accept_changed_version=payload.accept_changed_version,
        )
    except approval_service.CandidateNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except approval_service.VersionChanged as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except approval_service.VersionUnverifiable as exc:
        raise HTTPException(status_code=503, detail=str(exc))

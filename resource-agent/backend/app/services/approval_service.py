"""
approval_service.py
--------------------
The approval trust boundary (architecture.md 2.6, threat T2). This is plain,
deterministic Python: the LLM never calls into it and cannot bypass it.

    SEARCH -> SELECT -> APPROVE EXACT VERSION -> (re-verify) -> DOWNLOAD

Two entry points:
    approve_candidate(...)       - used by POST /resources/{id}/approve
    verify_active_approval(...)  - used by the download endpoint (next step)

Rule of thumb: if we cannot verify the current version, we FAIL CLOSED.
"""

from typing import Optional

from app import repository as repo
from app.services.version_resolver import is_pinned


class ApprovalServiceError(Exception):
    """Base class so routers can catch everything from this module."""


class CandidateNotFound(ApprovalServiceError):
    pass


class VersionUnverifiable(ApprovalServiceError):
    """Provider unreachable / rate-limited / unsupported. Nothing was changed."""


class VersionChanged(ApprovalServiceError):
    """Source changed since discovery. The user must explicitly re-confirm."""


class NoActiveApproval(ApprovalServiceError):
    pass


class ApprovalInvalidated(ApprovalServiceError):
    """The approval existed but the source changed after it; it is now invalidated."""


def approve_candidate(candidate_id: str, approved_by: str, resolver,
                      accept_changed_version: bool = False) -> dict:
    candidate = repo.get_candidate(candidate_id)
    if not candidate:
        raise CandidateNotFound("Resource not found")

    current = resolver.resolve(candidate)
    if not current:
        raise VersionUnverifiable(
            "Could not verify the resource's current version with its provider "
            "(unreachable, rate-limited or unsupported). Nothing was approved."
        )

    # Already approved for exactly this version -> idempotent, return it.
    existing = repo.get_active_approval_for_candidate(candidate_id)
    if existing:
        if existing["approved_version_or_commit"] == current:
            return existing
        repo.invalidate_approval(
            existing["id"],
            f"Source changed after approval: approved {existing['approved_version_or_commit']}, "
            f"now {current}",
        )

    discovered = candidate["version_or_commit"]
    if discovered != current:
        if is_pinned(discovered):
            # The user reviewed one exact version; the source now has another.
            if not accept_changed_version:
                raise VersionChanged(
                    f"The resource changed since it was discovered (discovered {discovered}, "
                    f"now {current}). Review it, then approve again with "
                    f"accept_changed_version=true to approve the new version."
                )
        # else: discovered version was a moving ref like 'main' (connector couldn't get a
        # commit id), so there was no exact version to protect - pin it now.
        candidate = repo.update_candidate_version(candidate_id, current)

    return repo.create_approval(candidate_id, approved_by)


def verify_active_approval(candidate_id: str, resolver) -> dict:
    """
    Call immediately before downloading. Returns the active approval only if the
    source is STILL at the approved version; otherwise invalidates it (FR6).
    """
    candidate = repo.get_candidate(candidate_id)
    if not candidate:
        raise CandidateNotFound("Resource not found")

    approval = repo.get_active_approval_for_candidate(candidate_id)
    if not approval:
        raise NoActiveApproval("No active approval for this resource. Approve it first.")

    current = resolver.resolve(candidate)
    if not current:
        # Do NOT invalidate: an outage is not evidence the source changed. Just refuse.
        raise VersionUnverifiable(
            "Could not verify the resource's current version, so the download is blocked."
        )

    approved = approval["approved_version_or_commit"]
    if current != approved:
        reason = f"Source changed after approval: approved {approved}, now {current}"
        repo.invalidate_approval(approval["id"], reason)
        raise ApprovalInvalidated(reason + ". The approval is no longer valid; approve again.")

    return approval

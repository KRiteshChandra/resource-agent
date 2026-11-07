"""
routers/downloads.py
---------------------
Implements (api-spec.yaml):
    POST /resources/{resource_id}/download   start a download of an APPROVED resource
    GET  /downloads/{download_id}            poll its status (added: needed because the download
                                             runs in the background and the POST returns 202)
    GET  /downloads/{download_id}/report     inspection report + provenance manifest

Thin HTTP layer. The rules live in services/approval_service.py (approval re-check) and
services/safe_downloader.py (fetching + safety checks). Nothing here asks the LLM anything.

Flow of POST /resources/{id}/download
  1. verify_active_approval(): the resource must have an ACTIVE approval AND the provider must
     still report the approved version. If the source changed, the approval is invalidated
     (FR6). Fails closed when the provider can't be reached.
  2. A `downloads` row is created with status "pending" and the response (202) returns at once.
  3. In the background: SafeDownloader fetches the approved commit into quarantine/<download_id>/.

Download status values
    pending      accepted, running in the background
    validated    downloaded; URL / size / file-type checks passed; files sit in quarantine
    complete     validated AND the file inspector produced a report
    quarantined  downloaded, but inspection rejected or could not process the files; files are
                 kept in quarantine and are NOT usable
    failed       refused or broken (blocked URL, too big, wrong file type, network error, ...)

Until services/file_inspector.py exists, successful downloads stop at "validated". The moment
that file is added it is picked up automatically (see get_inspector) with no change here.

Inspector contract (implemented in the next step):
    inspect_download(files: list[StoredFile]) -> dict   # keys: format, schema_preview, record_count, encoding
    It must raise an exception if the files are unsafe or can't be processed -> "quarantined".

Provenance: a provenance_manifests row is written for every successful download, and the same
data is saved as provenance.json next to the files (threat T10, audit trail).
"""

import json
import logging
import os
import threading
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from app import repository as repo
from app.models.schemas import Download, DownloadReport
from app.routers.approvals import get_version_resolver
from app.services import approval_service
from app.services.safe_downloader import DownloadError, SafeDownloader
from app.services.security_validator import effective_max_bytes

logger = logging.getLogger(__name__)
router = APIRouter(tags=["downloads"])

MIME_BY_TYPE = {
    "text": "text/plain",
    "zip": "application/zip",
    "pdf": "application/pdf",
    "png": "image/png",
    "jpeg": "image/jpeg",
    "parquet": "application/vnd.apache.parquet",
}

# One download per resource at a time (this app runs as a single local process).
_active: set = set()
_active_lock = threading.Lock()


def _claim(resource_id: str) -> bool:
    with _active_lock:
        if resource_id in _active:
            return False
        _active.add(resource_id)
        return True


def _release(resource_id: str) -> None:
    with _active_lock:
        _active.discard(resource_id)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Dependencies (tests swap these)
# ---------------------------------------------------------------------------

def get_downloader() -> SafeDownloader:
    return SafeDownloader()


def get_inspector():
    """
    Returns services.file_inspector.inspect_download if that module exists, else None.
    Only a missing file_inspector module is tolerated; any other import problem is raised
    so a real bug in the inspector is never silently ignored.
    """
    try:
        from app.services.file_inspector import inspect_download
    except ModuleNotFoundError as exc:
        if exc.name == "app.services.file_inspector":
            return None
        raise
    return inspect_download


# ---------------------------------------------------------------------------
# Background work
# ---------------------------------------------------------------------------

def _write_provenance_file(directory: str, data: dict) -> None:
    path = os.path.join(directory, "provenance.json")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags, 0o600), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def _execute(download_id, candidate, approval, max_bytes, downloader, inspector) -> None:
    try:
        result = downloader.download(
            candidate, approval["approved_version_or_commit"], download_id, max_bytes)
    except DownloadError as exc:
        repo.update_download(download_id, status="failed",
                             validation_notes={**exc.notes, "error": str(exc)})
        return

    files = [{"name": f.original_name, "stored_as": f.stored_name, "size": f.size,
              "sha256": f.sha256, "type": f.detected_type} for f in result.files]
    notes = {**result.notes, "files": files}
    downloaded_at = _now()
    mime = ",".join(sorted({MIME_BY_TYPE.get(f.detected_type, f.detected_type) for f in result.files}))

    repo.update_download(
        download_id, status="validated", local_path=result.directory, sha256=result.sha256,
        mime_detected=mime, size_bytes=result.total_bytes, downloaded_at=downloaded_at,
        validation_notes=notes)

    # Provenance manifest (DB row + file next to the downloaded data).
    repo.create_provenance_manifest(
        download_id=download_id, provider=candidate["provider"],
        original_source=candidate["source_url"],
        revision=approval["approved_version_or_commit"],
        approved_by=approval["approved_by"], approved_at=approval["approved_at"],
        license_evidence=candidate.get("license_evidence"),
        sha256=result.sha256, size_bytes=result.total_bytes,
        detected_format=result.detected_format)
    try:
        _write_provenance_file(result.directory, {
            "download_id": download_id, "provider": candidate["provider"],
            "original_source": candidate["source_url"],
            "revision": approval["approved_version_or_commit"],
            "approved_by": approval["approved_by"], "approved_at": approval["approved_at"],
            "license": candidate.get("license"),
            "license_evidence": candidate.get("license_evidence"),
            "sha256": result.sha256, "size_bytes": result.total_bytes,
            "detected_format": result.detected_format, "downloaded_at": downloaded_at,
            "files": files})
    except OSError:
        notes["provenance_file"] = "could not be written (the database record is still saved)"
        repo.update_download(download_id, validation_notes=notes)

    # Inspection (optional until the file inspector exists).
    if inspector is None:
        notes["inspection"] = "not run: file inspector is not installed yet"
        repo.update_download(download_id, validation_notes=notes)
        return
    try:
        report = inspector(result.files) or {}
        repo.create_inspection_report(
            download_id, report.get("format") or result.detected_format,
            report.get("schema_preview"), report.get("record_count"), report.get("encoding"))
    except Exception as exc:  # unsafe or unreadable -> hold in quarantine, never "complete"
        logger.warning("Inspection rejected download %s: %s", download_id, exc)
        notes["inspection_error"] = str(exc)[:300]
        repo.update_download(download_id, status="quarantined", validation_notes=notes)
        return
    repo.update_download(download_id, status="complete")


def _run_download(download_id, candidate, approval, max_bytes, downloader, inspector) -> None:
    try:
        _execute(download_id, candidate, approval, max_bytes, downloader, inspector)
    except Exception:
        logger.exception("Download %s crashed", download_id)
        try:  # generic text on purpose: never leak internals
            repo.update_download(download_id, status="failed",
                                 validation_notes={"error": "Unexpected internal error"})
        except Exception:
            logger.exception("Could not mark download %s as failed", download_id)
    finally:
        _release(candidate["id"])


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/resources/{resource_id}/download", response_model=Download, status_code=202)
def start_download(resource_id: str, background_tasks: BackgroundTasks,
                   resolver=Depends(get_version_resolver),
                   downloader=Depends(get_downloader),
                   inspector=Depends(get_inspector)):
    try:
        approval = approval_service.verify_active_approval(resource_id, resolver)
    except approval_service.CandidateNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except approval_service.NoActiveApproval as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except approval_service.ApprovalInvalidated as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except approval_service.VersionUnverifiable as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    candidate = repo.get_candidate(resource_id)
    requirement = repo.get_requirement(candidate["requirement_id"]) or {}
    max_bytes = effective_max_bytes(requirement.get("max_size_mb"))

    if not _claim(resource_id):
        raise HTTPException(status_code=409,
                            detail="A download for this resource is already in progress.")
    try:
        download = repo.create_download(approval["id"])
    except Exception:
        _release(resource_id)
        raise
    background_tasks.add_task(_run_download, download["id"], candidate, approval,
                              max_bytes, downloader, inspector)
    return download


@router.get("/downloads/{download_id}", response_model=Download)
def get_download_status(download_id: str):
    download = repo.get_download(download_id)
    if not download:
        raise HTTPException(status_code=404, detail="Download not found")
    return download


@router.get("/downloads/{download_id}/report", response_model=DownloadReport)
def get_download_report(download_id: str):
    if not repo.get_download(download_id):
        raise HTTPException(status_code=404, detail="Download not found")
    return repo.get_report_for_download(download_id)

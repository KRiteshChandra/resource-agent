"""
repository.py
-------------
Database access layer. Routers call these functions instead of writing
raw SQL directly.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.database import db_session


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Requirement
# ---------------------------------------------------------------------------

def create_requirement(raw_text: str, resource_types: list, topics: list,
                        preferred_formats: list, license_preference: Optional[str],
                        max_size_mb: Optional[int]) -> dict:
    req_id = _new_id()
    created_at = _now()
    with db_session() as conn:
        conn.execute(
            """INSERT INTO requirements
               (id, raw_text, resource_types, topics, preferred_formats,
                license_preference, max_size_mb, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (req_id, raw_text, json.dumps(resource_types), json.dumps(topics),
             json.dumps(preferred_formats), license_preference, max_size_mb, created_at),
        )
    return get_requirement(req_id)


def get_requirement(requirement_id: str) -> Optional[dict]:
    with db_session() as conn:
        row = conn.execute("SELECT * FROM requirements WHERE id = ?", (requirement_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["resource_types"] = json.loads(d["resource_types"])
    d["topics"] = json.loads(d["topics"])
    d["preferred_formats"] = json.loads(d["preferred_formats"])
    return d


def list_requirements() -> list[dict]:
    with db_session() as conn:
        rows = conn.execute("SELECT * FROM requirements ORDER BY created_at DESC").fetchall()
    out = []
    for row in rows:
        d = dict(row)
        d["resource_types"] = json.loads(d["resource_types"])
        d["topics"] = json.loads(d["topics"])
        d["preferred_formats"] = json.loads(d["preferred_formats"])
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# Candidate
# ---------------------------------------------------------------------------

def create_candidate(requirement_id: str, provider: str, source_url: str,
                      version_or_commit: str, title: str, description: str,
                      format: str, size_bytes: Optional[int], license: Optional[str],
                      license_evidence: Optional[str], relevance_score: float,
                      score_breakdown: dict) -> dict:
    cand_id = _new_id()
    discovered_at = _now()
    with db_session() as conn:
        conn.execute(
            """INSERT INTO candidates
               (id, requirement_id, provider, source_url, version_or_commit, title,
                description, format, size_bytes, license, license_evidence,
                relevance_score, score_breakdown, discovered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (cand_id, requirement_id, provider, source_url, version_or_commit, title,
             description, format, size_bytes, license, license_evidence,
             relevance_score, json.dumps(score_breakdown), discovered_at),
        )
    return get_candidate(cand_id)


def get_candidate(candidate_id: str) -> Optional[dict]:
    with db_session() as conn:
        row = conn.execute("SELECT * FROM candidates WHERE id = ?", (candidate_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["score_breakdown"] = json.loads(d["score_breakdown"]) if d["score_breakdown"] else {}
    return d


def list_candidates_for_requirement(requirement_id: str) -> list[dict]:
    with db_session() as conn:
        rows = conn.execute(
            "SELECT * FROM candidates WHERE requirement_id = ? ORDER BY relevance_score DESC",
            (requirement_id,),
        ).fetchall()
    out = []
    for row in rows:
        d = dict(row)
        d["score_breakdown"] = json.loads(d["score_breakdown"]) if d["score_breakdown"] else {}
        out.append(d)
    return out


def update_candidate_version(candidate_id: str, version_or_commit: str) -> Optional[dict]:
    """
    NEW in the approval step. Pins a candidate to an exact version. Only
    approval_service calls this: either the stored version was a moving ref
    like 'main', or the user explicitly accepted a changed version.
    """
    with db_session() as conn:
        conn.execute(
            "UPDATE candidates SET version_or_commit = ? WHERE id = ?",
            (version_or_commit, candidate_id),
        )
    return get_candidate(candidate_id)


# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------

def create_approval(candidate_id: str, approved_by: str) -> dict:
    candidate = get_candidate(candidate_id)
    if not candidate:
        raise ValueError("Candidate not found")

    approval_id = _new_id()
    approved_at = _now()
    with db_session() as conn:
        conn.execute(
            """INSERT INTO approvals
               (id, candidate_id, approved_version_or_commit, approved_by,
                approved_at, status, invalidated_reason)
               VALUES (?, ?, ?, ?, ?, 'active', NULL)""",
            (approval_id, candidate_id, candidate["version_or_commit"], approved_by, approved_at),
        )
    return get_approval(approval_id)


def get_approval(approval_id: str) -> Optional[dict]:
    with db_session() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
    return dict(row) if row else None


def get_active_approval_for_candidate(candidate_id: str) -> Optional[dict]:
    with db_session() as conn:
        row = conn.execute(
            """SELECT * FROM approvals
               WHERE candidate_id = ? AND status = 'active'
               ORDER BY approved_at DESC LIMIT 1""",
            (candidate_id,),
        ).fetchone()
    return dict(row) if row else None


def invalidate_approval(approval_id: str, reason: str) -> None:
    with db_session() as conn:
        conn.execute(
            "UPDATE approvals SET status = 'invalidated', invalidated_reason = ? WHERE id = ?",
            (reason, approval_id),
        )


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def create_download(approval_id: str) -> dict:
    download_id = _new_id()
    with db_session() as conn:
        conn.execute(
            """INSERT INTO downloads
               (id, approval_id, status, local_path, sha256, mime_detected,
                size_bytes, downloaded_at, validation_notes)
               VALUES (?, ?, 'pending', NULL, NULL, NULL, NULL, NULL, '{}')""",
            (download_id, approval_id),
        )
    return get_download(download_id)


def update_download(download_id: str, **fields) -> dict:
    allowed = {"status", "local_path", "sha256", "mime_detected", "size_bytes",
               "downloaded_at", "validation_notes"}
    sets, values = [], []
    for k, v in fields.items():
        if k not in allowed:
            continue
        if k == "validation_notes" and isinstance(v, dict):
            v = json.dumps(v)
        sets.append(f"{k} = ?")
        values.append(v)
    if not sets:
        return get_download(download_id)
    values.append(download_id)
    with db_session() as conn:
        conn.execute(f"UPDATE downloads SET {', '.join(sets)} WHERE id = ?", values)
    return get_download(download_id)


def get_download(download_id: str) -> Optional[dict]:
    with db_session() as conn:
        row = conn.execute("SELECT * FROM downloads WHERE id = ?", (download_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["validation_notes"] = json.loads(d["validation_notes"]) if d["validation_notes"] else {}
    return d


# ---------------------------------------------------------------------------
# Inspection + Provenance
# ---------------------------------------------------------------------------

def create_inspection_report(download_id: str, format: str, schema_preview: Optional[dict],
                              record_count: Optional[int], encoding: Optional[str]) -> dict:
    report_id = _new_id()
    generated_at = _now()
    with db_session() as conn:
        conn.execute(
            """INSERT INTO inspection_reports
               (id, download_id, format, schema_preview, record_count, encoding, generated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (report_id, download_id, format,
             json.dumps(schema_preview) if schema_preview else None,
             record_count, encoding, generated_at),
        )
    with db_session() as conn:
        row = conn.execute("SELECT * FROM inspection_reports WHERE id = ?", (report_id,)).fetchone()
    d = dict(row)
    d["schema_preview"] = json.loads(d["schema_preview"]) if d["schema_preview"] else None
    return d


def create_provenance_manifest(download_id: str, provider: str, original_source: str,
                                revision: str, approved_by: str, approved_at: str,
                                license_evidence: Optional[str], sha256: str,
                                size_bytes: int, detected_format: str) -> dict:
    manifest_id = _new_id()
    with db_session() as conn:
        conn.execute(
            """INSERT INTO provenance_manifests
               (id, download_id, provider, original_source, revision, approved_by,
                approved_at, license_evidence, sha256, size_bytes, detected_format)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (manifest_id, download_id, provider, original_source, revision, approved_by,
             approved_at, license_evidence, sha256, size_bytes, detected_format),
        )
    with db_session() as conn:
        row = conn.execute(
            "SELECT * FROM provenance_manifests WHERE id = ?", (manifest_id,)
        ).fetchone()
    return dict(row)


def get_report_for_download(download_id: str) -> dict:
    with db_session() as conn:
        insp = conn.execute(
            "SELECT * FROM inspection_reports WHERE download_id = ?", (download_id,)
        ).fetchone()
        prov = conn.execute(
            "SELECT * FROM provenance_manifests WHERE download_id = ?", (download_id,)
        ).fetchone()
    inspection = None
    if insp:
        inspection = dict(insp)
        inspection["schema_preview"] = (
            json.loads(inspection["schema_preview"]) if inspection["schema_preview"] else None
        )
    provenance = dict(prov) if prov else None
    return {"inspection": inspection, "provenance": provenance}

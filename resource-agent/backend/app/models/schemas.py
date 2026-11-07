"""
schemas.py
----------
Pydantic models used for request/response validation across the API.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class Provider(str, Enum):
    github = "github"
    huggingface = "huggingface"
    web = "web"


class ApprovalStatus(str, Enum):
    active = "active"
    invalidated = "invalidated"


class DownloadStatus(str, Enum):
    pending = "pending"
    validated = "validated"
    quarantined = "quarantined"
    failed = "failed"
    complete = "complete"


class RequirementCreate(BaseModel):
    raw_text: str = Field(..., min_length=3, description="Natural language request from the user")


class Requirement(BaseModel):
    id: str
    raw_text: str
    resource_types: list[str]
    topics: list[str]
    preferred_formats: list[str]
    license_preference: Optional[str] = None
    max_size_mb: Optional[int] = None
    created_at: str


class Candidate(BaseModel):
    id: str
    requirement_id: str
    provider: str
    source_url: str
    version_or_commit: str
    title: str
    description: Optional[str] = None
    format: Optional[str] = None
    size_bytes: Optional[int] = None
    license: Optional[str] = None
    license_evidence: Optional[str] = None
    relevance_score: float
    score_breakdown: dict
    discovered_at: str


class ApprovalCreate(BaseModel):
    approved_by: str = Field(..., description="Identifier of the user approving this resource")


class Approval(BaseModel):
    id: str
    candidate_id: str
    approved_version_or_commit: str
    approved_by: str
    approved_at: str
    status: ApprovalStatus
    invalidated_reason: Optional[str] = None


class Download(BaseModel):
    id: str
    approval_id: str
    status: DownloadStatus
    local_path: Optional[str] = None
    sha256: Optional[str] = None
    mime_detected: Optional[str] = None
    size_bytes: Optional[int] = None
    downloaded_at: Optional[str] = None
    validation_notes: dict = Field(default_factory=dict)


class InspectionReport(BaseModel):
    format: Optional[str] = None
    schema_preview: Optional[dict] = None
    record_count: Optional[int] = None
    encoding: Optional[str] = None


class ProvenanceManifest(BaseModel):
    provider: Optional[str] = None
    original_source: Optional[str] = None
    revision: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    license_evidence: Optional[str] = None
    sha256: Optional[str] = None
    size_bytes: Optional[int] = None
    detected_format: Optional[str] = None


class DownloadReport(BaseModel):
    inspection: Optional[InspectionReport] = None
    provenance: Optional[ProvenanceManifest] = None

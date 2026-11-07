# Data Model — AI Resource Acquisition Agent

## 1. Entities

### 1.1 Requirement
Parsed representation of the user's natural-language request.

| Field | Type | Notes |
|---|---|---|
| id | UUID | primary key |
| raw_text | string | original user input |
| resource_types | list[string] | e.g. ["dataset", "repository"] |
| topics | list[string] | e.g. ["IT support tickets", "incident resolution"] |
| preferred_formats | list[string] | e.g. ["csv", "json"] |
| license_preference | string | e.g. "permissive", "any", "commercial-use-ok" |
| max_size_mb | int (nullable) | optional budget/size constraint |
| created_at | datetime | |

### 1.2 Candidate (Resource)
A single discovered item from a connector, before approval.

| Field | Type | Notes |
|---|---|---|
| id | UUID | primary key |
| requirement_id | UUID | FK → Requirement |
| provider | string | "github" \| "huggingface" \| "web" |
| source_url | string | canonical link to resource |
| version_or_commit | string | exact version/commit/revision identifier |
| title | string | |
| description | string | |
| format | string | e.g. "csv", "parquet", "repo" |
| size_bytes | int (nullable) | |
| license | string (nullable) | detected license, if any |
| license_evidence | string (nullable) | where license info was found |
| relevance_score | float | 0–1, from ranking engine |
| score_breakdown | json | per-factor scores for explainability |
| discovered_at | datetime | |

### 1.3 Approval
Links a user's explicit decision to one exact Candidate version.

| Field | Type | Notes |
|---|---|---|
| id | UUID | primary key |
| candidate_id | UUID | FK → Candidate |
| approved_version_or_commit | string | locked at approval time |
| approved_by | string | user identifier |
| approved_at | datetime | |
| status | enum | "active" \| "invalidated" |
| invalidated_reason | string (nullable) | e.g. "source URL changed after approval" |

### 1.4 Download
Record of an actual download attempt/result.

| Field | Type | Notes |
|---|---|---|
| id | UUID | primary key |
| approval_id | UUID | FK → Approval |
| status | enum | "pending" \| "validated" \| "quarantined" \| "failed" \| "complete" |
| local_path | string | quarantine/storage path |
| sha256 | string | |
| mime_detected | string | |
| size_bytes | int | |
| downloaded_at | datetime | |
| validation_notes | json | SSRF/redirect/MIME check results |

### 1.5 InspectionReport
| Field | Type | Notes |
|---|---|---|
| id | UUID | primary key |
| download_id | UUID | FK → Download |
| format | string | |
| schema_preview | json (nullable) | e.g. column names/types for CSV |
| record_count | int (nullable) | |
| encoding | string (nullable) | |
| generated_at | datetime | |

### 1.6 ProvenanceManifest
| Field | Type | Notes |
|---|---|---|
| id | UUID | primary key |
| download_id | UUID | FK → Download |
| provider | string | |
| original_source | string | |
| revision | string | |
| approved_by | string | |
| approved_at | datetime | |
| license_evidence | string (nullable) | |
| sha256 | string | |
| size_bytes | int | |
| detected_format | string | |

## 2. Relationships
```
Requirement 1 ──< Candidate 1 ──< Approval 1 ──< Download 1 ──< InspectionReport
                                                        └──< ProvenanceManifest
```

## 3. Notes
- `version_or_commit` is the field that enforces FR6 (approval invalidated if source changes) — it must be compared exactly at download time against the Approval record.
- `score_breakdown` is stored as JSON specifically to support the explainable-ranking requirement (NFR4) in the UI.

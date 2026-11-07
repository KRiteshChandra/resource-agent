# Implementation Plan — AI Resource Acquisition Agent

## Stage 1 — Planning (this step)
- [x] requirements.md
- [x] architecture.md
- [x] data-model.md
- [x] api-spec.yaml
- [x] threat-model.md
- [x] implementation-plan.md (this file)

Goal: no code written until the shape of the system is agreed on paper. Prevents rework and gives a clean reference while debugging later.

## Stage 2 — MVP Vertical Slice
**Goal:** `Request → GitHub + Hugging Face search → 5 candidates → approval → download blocked unless approved`

Backend tasks:
1. FastAPI project skeleton + SQLite setup (SQLAlchemy models from data-model.md)
2. `Requirement` parsing endpoint (`POST /requests`) — rule-based or lightweight LLM-assisted parser
3. `GitHubConnector` — public repo/file search, works without token (rate-limited) or with `GITHUB_TOKEN`
4. `HuggingFaceConnector` — public dataset search, works without token or with `HF_TOKEN`
5. `WebSearchConnector` — stub returning empty results, ready to be wired later
6. Normalizer/Deduplicator — merge connector outputs into common `Candidate` schema
7. Ranking Engine v1 — simple weighted scoring (relevance, format match, license evidence presence)
8. `POST /resources/{id}/approve` — creates Approval, locks `version_or_commit`
9. `POST /resources/{id}/download` — blocked unless active Approval exists and version matches

Frontend tasks:
1. React + TypeScript scaffold (Vite)
2. Request input form → calls `POST /requests`
3. Ranked resource cards (provider, title, format, license, score, evidence)
4. Separate **Approve** and **Download** buttons per card
5. Simple status indicator (pending / approved / downloading / blocked)

**Exit criteria for Stage 2:** You can type a real request, see real GitHub + Hugging Face results ranked, approve one, and confirm download is blocked if you try to download an un-approved or changed resource.

## Stage 3 — Security Hardening + Inspection
1. Security Validator: SSRF protection, redirect validation, size limits
2. Safe Downloader: randomized filenames, quarantine folder, no auto-execution
3. MIME/signature verification + SHA-256 hashing
4. Archive-bomb/path-traversal protection for zipped resources
5. File Inspector for CSV/JSON/JSONL/TXT/Markdown/PDF/images
6. Provenance Manifest generation per download
7. `GET /downloads/{id}/report` endpoint + frontend report view

**Exit criteria:** Every download produces a provenance manifest and inspection report; malicious/oversized/mismatched files are rejected with a clear reason shown in the UI.

## Stage 4 — Expansion (only after Stage 2 + 3 are solid)
1. Wire in a real web-search connector (Brave or Tavily) behind the existing stub interface
2. Improve ranking engine (better relevance scoring, maybe embeddings-based similarity)
3. Optional: Kaggle connector
4. Optional: basic auth if moving beyond single-user local use

## Suggested Build Order (this conversation)
We will go file-by-file, in this order, so each piece can be tested before moving to the next:
1. Backend project skeleton + models + DB setup
2. GitHub connector
3. Hugging Face connector
4. Requirement parser + `/requests` endpoint
5. Ranking engine + `/requests/{id}/resources` endpoint
6. Approval endpoint + invalidation logic
7. Download endpoint (with security validator stubbed initially, hardened in Stage 3)
8. Frontend: request form → results → approve/download

## Resume-Relevant Framing (for later)
Each stage maps to a distinct, describable skill for your resume/interviews:
- Stage 1 → requirements analysis, system design, threat modeling
- Stage 2 → full-stack API integration (FastAPI + React), external REST API consumption
- Stage 3 → application security (SSRF prevention, file validation, provenance/audit trails)
- Stage 4 → extensible connector architecture, search relevance tuning

# Architecture — AI Resource Acquisition Agent

## 1. High-Level Diagram

```
React + TypeScript (UI)
        |
        v
     FastAPI (backend)
        |
        v
Requirements Parser (LLM-assisted)
        |
        v
Discovery Orchestrator
   /          \
GitHub      HuggingFace     (Web Search — stubbed in MVP)
   \          /
    v        v
Normalizer / Deduplicator
        |
        v
Ranking Engine (explainable scoring)
        |
        v
      SQLite (resources, requests, approvals)
        |
        v
User Approval (exact version/URL lock)
        |
        v
Security Validator (SSRF, MIME, size checks)
        |
        v
Safe Downloader
        |
        v
   Quarantine folder
        |
        v
File Inspector (format-aware)
        |
        v
Report + Provenance Manifest
```

## 2. Components

### 2.1 Frontend (React + TypeScript)
- Request input form
- Ranked resource cards (source, provider, format, license, size, evidence)
- Separate, distinct **Approve** and **Download** actions (never combined into one click)
- Status/report view after download completes

### 2.2 Backend (FastAPI)
Responsible for all business logic, security enforcement, and persistence. The LLM is used only for:
- Parsing natural language into a structured requirement object
- Generating human-readable explanations for ranking

The LLM is **never** allowed to trigger a download or bypass approval — that logic is deterministic Python code.

### 2.3 Connectors
Each connector implements a common interface: `search(requirement) -> List[Candidate]`.
- `GitHubConnector` — searches public repositories/files via GitHub REST API
- `HuggingFaceConnector` — searches public datasets via Hugging Face Hub API
- `WebSearchConnector` — stub in MVP; wired to a provider (e.g., Brave/Tavily) later without touching other components

### 2.4 Normalizer / Deduplicator
Converts each connector's raw response into a common `Candidate` schema and removes duplicate resources returned by multiple sources.

### 2.5 Ranking Engine
Scores candidates using transparent, explainable factors:
- Topical relevance to the parsed requirement
- Resource type match
- Format compatibility
- License evidence strength
- Schema/documentation availability
- Size constraint fit

The score is a **ranking aid only** — it never claims a resource is legally safe to reuse.

### 2.6 Approval Flow (core trust boundary)
```
SEARCH → SELECT → APPROVE EXACT VERSION → VALIDATE → DOWNLOAD
```
If the URL or version changes after approval, the approval record is invalidated automatically. This check lives in the backend, not the LLM.

### 2.7 Security Validator / Safe Downloader
- Blocks localhost / private network targets (SSRF protection)
- Validates redirects before following them
- Enforces download size limits
- Generates safe, randomized filenames
- Verifies MIME type against file signature (magic bytes)
- Computes SHA-256 hash
- Guards against archive bombs and path traversal in zipped content
- Never auto-executes scripts, notebooks, or binaries

### 2.8 File Inspector
Supports (MVP): CSV, JSON, JSONL, TXT, Markdown, PDF, images.
Produces a structured inspection report (schema preview, row/record counts, detected encoding, etc.).

### 2.9 Provenance Manifest
For every approved + downloaded resource, records:
- Original source and provider
- Resource revision/version
- Download timestamp
- Approval record (who approved, when)
- License evidence
- File hash and size
- Detected format

## 3. Data Store
SQLite for MVP (file-based, zero-config) — can migrate to Postgres later without changing the API layer, since access is abstracted behind a repository layer.

## 4. Key Design Principle
**Separation of concerns between the LLM and the application core.** The LLM interprets and explains; deterministic backend code enforces approval, security, and auditability. This is the single most important architectural decision in the system and should be preserved in every future extension.

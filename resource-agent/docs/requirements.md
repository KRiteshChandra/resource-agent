# Requirements — AI Resource Acquisition Agent

## 1. Purpose
An AI-assisted agent that helps a user find, evaluate, approve, and safely download external resources (datasets, code repositories, documents) based on a natural-language request — without the AI ever downloading anything on its own authority.

## 2. Problem Statement
Finding the right dataset or repository for a task (e.g., "I need IT support ticket datasets") usually means manually searching multiple sites, checking licenses, and verifying the content is trustworthy before using it. This project automates **discovery and evaluation**, while keeping **download and execution** strictly gated behind explicit human approval.

## 3. Core User Flow
1. User types a plain-language request (e.g., "Find datasets of system logs and incident resolutions").
2. Backend parses this into a structured requirement (resource type, topic, format, license preference, size limit).
3. Backend queries connectors (GitHub, Hugging Face, later: web search) for candidates.
4. Candidates are normalized, deduplicated, and ranked with visible evidence (why this result was suggested).
5. User reviews ranked cards and **approves exactly one specific version/URL** of a resource.
6. Only after approval can the **Download** action be triggered.
7. Downloaded file passes through security validation and inspection before being marked usable.
8. A provenance report is generated (source, license evidence, hash, timestamp).

## 4. Functional Requirements

| ID | Requirement |
|----|-------------|
| FR1 | User can submit a natural-language resource request |
| FR2 | System parses request into a structured, validated requirement object |
| FR3 | System queries at least GitHub and Hugging Face for candidate resources |
| FR4 | System deduplicates and ranks candidates with explainable scoring |
| FR5 | User must explicitly approve an exact resource version before any download is allowed |
| FR6 | Changing the resource URL/version after approval invalidates the approval |
| FR7 | Downloads are validated for safety (SSRF protection, MIME/signature checks, size limits) before being accepted |
| FR8 | System generates an inspection report and provenance manifest for every downloaded resource |
| FR9 | System never auto-executes downloaded scripts, notebooks, or binaries |

## 5. Non-Functional Requirements

| ID | Requirement |
|----|-------------|
| NFR1 | Security: approval and download enforcement must live in backend code, never in the LLM layer |
| NFR2 | Extensibility: new connectors (e.g., Kaggle, web search) must be addable without changing core architecture |
| NFR3 | Auditability: every approval and download must be traceable (who/when/what) |
| NFR4 | Usability: ranked results must show *why* each candidate was suggested, not just a score |
| NFR5 | Resilience: a missing or invalid API key for one connector must not break the rest of the system |

## 6. Out of Scope (v1)
- Automatic execution of downloaded code/notebooks
- Paid/gated dataset access
- Multi-user accounts or team collaboration features
- Kaggle and other connectors beyond GitHub, Hugging Face, and (later) one web-search provider

## 7. MVP Definition (Milestone 1)
`Request → GitHub + Hugging Face search → ranked candidates → manual approval → download blocked unless approved`

No web-search connector, no advanced inspection — just the core approval-gated discovery pipeline, built end-to-end and working.

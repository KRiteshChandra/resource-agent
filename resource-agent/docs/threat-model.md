# Threat Model — AI Resource Acquisition Agent

## 1. Trust Boundaries

```
[Untrusted]            [Semi-trusted]           [Trusted]
External sources  -->  LLM interpretation  -->  Backend enforcement layer
(GitHub, HF, web)      (parsing, ranking,        (approval, validation,
                        explanations only)        download, storage)
```

The core principle: **the LLM can suggest and explain, but never execute or authorize.** Every destructive or trust-sensitive action (download, file write, approval check) is enforced by deterministic backend code that does not consult the LLM at execution time.

## 2. Key Threats and Mitigations

| # | Threat | Mitigation |
|---|---|---|
| T1 | **Prompt injection** via a malicious dataset description/README tricking the LLM into recommending or "approving" an unsafe resource | LLM output is treated as a suggestion only; approval requires an explicit, separate user action tied to a specific resource ID. LLM never has approve/download authority. |
| T2 | **Approval bypass via URL/version swap** — a source changes content after being approved (classic TOCTOU attack) | `version_or_commit` is locked at approval time; download endpoint re-validates it matches exactly before proceeding. Mismatch invalidates the approval (FR6). |
| T3 | **SSRF (Server-Side Request Forgery)** — a malicious or redirected URL points to localhost/internal network/cloud metadata endpoint | Block requests to localhost, private IP ranges (RFC1918), link-local, and cloud metadata IPs (e.g., 169.254.169.254) before every outbound fetch. Validate every redirect hop, not just the initial URL. |
| T4 | **Malicious file content** — downloaded "dataset" is actually an executable, script, or disguised malware | MIME type verified against file signature (magic bytes), not just file extension or declared content-type. Files are never auto-executed; downloaded content goes to quarantine first. |
| T5 | **Archive bombs / path traversal** — a zip/tar file that decompresses to huge size or writes outside the intended directory | Enforce decompression size limits and reject entries with `../` or absolute paths before extraction. |
| T6 | **Resource exhaustion** — extremely large files consuming disk/bandwidth | Enforce `max_size_mb` from the Requirement and a hard server-side cap regardless of user input. |
| T7 | **Credential leakage** — API keys for GitHub/Hugging Face/LLM exposed to frontend or committed to source control | All keys live only in backend `.env`, never sent to frontend, `.env` is gitignored, `.env.example` ships with placeholders only. |
| T8 | **False license claims** — ranking engine or LLM implies a resource is "safe to use" when license is unclear or absent | License field is always paired with `license_evidence`; UI and reports explicitly state "license evidence found" rather than asserting legal clearance. Scoring never outputs a binary "safe/unsafe" claim. |
| T9 | **Rate-limit/availability abuse** — unauthenticated or misconfigured connector calls exhausting a provider's quota | Each connector call wrapped with backoff/retry limits; missing/invalid key for one connector degrades gracefully without blocking the others (NFR5). |
| T10 | **Audit gap** — no record of who approved/downloaded what, when | Every Approval and Download record stores actor, timestamp, and status; ProvenanceManifest persists this alongside the file itself. |

## 3. Residual Risks (accepted for MVP)
- No authentication/authorization system yet — single-user local tool assumption for MVP. Must be added before any multi-user or hosted deployment.
- Web-search connector is stubbed in MVP, so T1/T3 exposure from arbitrary web content is deferred until that connector is implemented — at which point this threat model must be revisited.
- No virus-scanning engine integration in MVP; MIME/signature checks are a first layer, not a full AV solution.

## 4. Design Rule Going Forward
Any new connector or feature must be checked against this table before being added. If it introduces a new way to reach T1–T10, add a corresponding mitigation before merging — don't rely on the LLM layer to "be careful."

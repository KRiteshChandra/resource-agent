"""
version_resolver.py
--------------------
Asks the provider (GitHub / Hugging Face) "what is the exact version of this
resource RIGHT NOW?". The approval flow compares that answer with the version
the user approved (threat T2: approval bypass via a version swap).

Security notes (threat T3, SSRF):
  * We NEVER fetch the candidate's source_url itself. We only extract
    owner/name segments from it, validate them, and build the request URL on
    top of a fixed API base (api.github.com / huggingface.co/api).
  * Redirects are not followed (httpx default).
  * Any failure returns None, and callers must treat None as "could not verify"
    and fail CLOSED (never approve or download on an unverified version).
"""

import os
import re
from typing import Optional
from urllib.parse import urlsplit

import httpx

GITHUB_API_BASE = "https://api.github.com"
HF_API_BASE = "https://huggingface.co/api"

# Git commit ids: 40 hex chars (SHA-1) or 64 (SHA-256 repos).
_PINNED = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]+$")


def is_pinned(version: Optional[str]) -> bool:
    """True if `version` is an exact commit id (not a moving ref like 'main')."""
    return bool(version) and bool(_PINNED.match(version))


def _valid_segment(segment: str) -> bool:
    return bool(_SEGMENT.match(segment)) and segment not in (".", "..")


def parse_github_url(url: str) -> Optional[tuple[str, str]]:
    """'https://github.com/owner/repo' -> ('owner', 'repo'); anything odd -> None."""
    parts = urlsplit(url or "")
    if parts.scheme != "https" or (parts.hostname or "").lower() not in ("github.com", "www.github.com"):
        return None
    segments = [s for s in parts.path.split("/") if s]
    if len(segments) != 2:
        return None
    owner, repo = segments
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not (_valid_segment(owner) and _valid_segment(repo)):
        return None
    return owner, repo


def parse_huggingface_dataset_url(url: str) -> Optional[str]:
    """'https://huggingface.co/datasets/ns/name' (or just /datasets/name) -> 'ns/name'."""
    parts = urlsplit(url or "")
    if parts.scheme != "https" or (parts.hostname or "").lower() != "huggingface.co":
        return None
    segments = [s for s in parts.path.split("/") if s]
    if len(segments) not in (2, 3) or segments[0] != "datasets":
        return None
    dataset_parts = segments[1:]
    if not all(_valid_segment(s) for s in dataset_parts):
        return None
    return "/".join(dataset_parts)


class VersionResolver:
    """resolve(candidate) -> current exact version string, or None if it can't be verified."""

    def __init__(self, github_token: Optional[str] = None, hf_token: Optional[str] = None,
                 timeout: float = 10.0, transport: Optional[httpx.BaseTransport] = None):
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.hf_token = hf_token or os.getenv("HF_TOKEN")
        self.timeout = timeout
        self._transport = transport  # only used by tests

    def resolve(self, candidate: dict) -> Optional[str]:
        provider = candidate.get("provider")
        url = candidate.get("source_url") or ""
        try:
            if provider == "github":
                return self._github(url)
            if provider == "huggingface":
                return self._huggingface(url)
        except (httpx.HTTPError, ValueError):
            return None
        return None  # e.g. "web": no way to pin a version yet

    def _github(self, url: str) -> Optional[str]:
        parsed = parse_github_url(url)
        if not parsed:
            return None
        owner, repo = parsed
        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        with httpx.Client(timeout=self.timeout, transport=self._transport) as client:
            # Latest commit on the default branch (documented: GET /repos/{o}/{r}/commits).
            resp = client.get(f"{GITHUB_API_BASE}/repos/{owner}/{repo}/commits",
                              headers=headers, params={"per_page": 1})
        if resp.status_code != 200:
            return None
        data = resp.json()
        sha = data[0].get("sha") if isinstance(data, list) and data else None
        return sha if is_pinned(sha) else None

    def _huggingface(self, url: str) -> Optional[str]:
        dataset_id = parse_huggingface_dataset_url(url)
        if not dataset_id:
            return None
        headers = {"Accept": "application/json"}
        if self.hf_token:
            headers["Authorization"] = f"Bearer {self.hf_token}"
        with httpx.Client(timeout=self.timeout, transport=self._transport) as client:
            resp = client.get(f"{HF_API_BASE}/datasets/{dataset_id}", headers=headers)
        if resp.status_code != 200:
            return None
        data = resp.json()
        sha = data.get("sha") if isinstance(data, dict) else None
        return sha if is_pinned(sha) else None

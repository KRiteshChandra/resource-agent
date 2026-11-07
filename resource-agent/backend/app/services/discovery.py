"""
discovery.py
-------------
Discovery orchestrator: runs every connector, then normalizes, ranks and
de-duplicates the combined results (architecture.md sections 2.3 - 2.5).

Rules:
  * One connector failing must never break the others (NFR5).
  * Candidates missing a source_url or version are dropped, because the
    approval flow locks on `version_or_commit` (threat T2) and the DB requires both.
"""

import logging
from urllib.parse import urlsplit

from app.services.ranking_engine import rank_candidates

logger = logging.getLogger(__name__)

PER_CONNECTOR_LIMIT = 5
MAX_CANDIDATES = 10


def normalize_url(url: str) -> str:
    """Lowercase host/path, drop trailing slash and '.git', so duplicates match."""
    parts = urlsplit((url or "").strip())
    path = parts.path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    return f"{parts.netloc.lower()}{path.lower()}"


def _is_valid(candidate: dict) -> bool:
    return bool(candidate.get("source_url")) and bool(candidate.get("version_or_commit"))


def deduplicate(ranked_candidates: list[dict]) -> list[dict]:
    """Input must be best-first; the first (best) copy of each URL wins."""
    seen: set[str] = set()
    unique = []
    for cand in ranked_candidates:
        key = normalize_url(cand["source_url"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(cand)
    return unique


def discover(requirement: dict, connectors: list) -> list[dict]:
    raw: list[dict] = []
    for connector in connectors:
        name = getattr(connector, "name", connector.__class__.__name__)
        try:
            found = connector.search(requirement, max_results=PER_CONNECTOR_LIMIT)
            logger.info("Connector %s returned %d candidates", name, len(found))
            raw.extend(found)
        except Exception as exc:  # isolate failures per connector
            logger.warning("Connector %s failed: %s", name, exc)

    valid = [c for c in raw if _is_valid(c)]
    ranked = rank_candidates(valid, requirement)
    return deduplicate(ranked)[:MAX_CANDIDATES]

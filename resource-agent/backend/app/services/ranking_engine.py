"""
ranking_engine.py
------------------
Scores every candidate (from ANY connector) with ONE consistent, explainable
formula, so GitHub and Hugging Face results can be compared fairly.

Important (threat-model T8): the score is a RANKING AID only. It never says a
resource is legally safe or fit to reuse - it only reflects how well the
evidence we could see matches what the user asked for.

Factors (weights sum to 1.0):
    topical_relevance   0.40  - do the requested topic words appear in title/description?
    resource_type_match 0.15  - repo vs dataset vs what the user asked for
    license_evidence    0.15  - license reported by the provider (and preference fit)
    format_match        0.10  - preferred file formats mentioned in the metadata
    size_fit            0.10  - within the user's size limit (if any)
    popularity_signal   0.10  - weak tie-breaker, taken from the connector's own signal
"""

import re

WEIGHTS = {
    "topical_relevance": 0.40,
    "resource_type_match": 0.15,
    "license_evidence": 0.15,
    "format_match": 0.10,
    "size_fit": 0.10,
    "popularity_signal": 0.10,
}

# SPDX ids / HF license tags we treat as "permissive" when the user asks for it.
PERMISSIVE_LICENSES = {
    "mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "isc",
    "unlicense", "cc0-1.0", "cc-by-4.0", "0bsd",
}

_TOKEN = re.compile(r"[a-z0-9]+")
_STOP = {"a", "an", "the", "of", "and", "or", "for", "with", "in", "on", "to", "it"}


def _tokens(text: str) -> set[str]:
    """Lowercase word tokens with a crude plural strip ('tickets' -> 'ticket')."""
    out = set()
    for tok in _TOKEN.findall((text or "").lower()):
        if tok in _STOP or len(tok) < 2:
            continue
        if len(tok) > 3 and tok.endswith("s"):
            tok = tok[:-1]
        out.add(tok)
    return out


def _topical_relevance(candidate: dict, requirement: dict, evidence: list) -> float:
    text = f"{candidate.get('title', '')} {candidate.get('description', '')}"
    cand_tokens = _tokens(text)
    topics = requirement.get("topics", [])
    if not topics:
        return 0.0

    per_topic = []
    for topic in topics:
        topic_tokens = _tokens(topic)
        if not topic_tokens:
            continue
        frac = len(topic_tokens & cand_tokens) / len(topic_tokens)
        per_topic.append(frac)
        if frac > 0:
            evidence.append(f"Topic '{topic}': {round(frac * 100)}% of its words found in title/description")
    return sum(per_topic) / len(per_topic) if per_topic else 0.0


def _type_match(candidate: dict, requirement: dict, evidence: list) -> float:
    wanted = [t.lower() for t in requirement.get("resource_types", [])]
    actual = (candidate.get("format") or "").lower()  # connectors set "repository" / "dataset"
    if not wanted:
        return 1.0
    if actual in wanted:
        evidence.append(f"Resource type '{actual}' matches the request")
        return 1.0
    evidence.append(f"Resource type '{actual or 'unknown'}' differs from requested {wanted}")
    return 0.4


def _license_score(candidate: dict, requirement: dict, evidence: list) -> float:
    lic = (candidate.get("license") or "").strip().lower()
    pref = (requirement.get("license_preference") or "any").lower()

    if not lic or lic in ("noassertion", "other"):
        evidence.append("No clear license reported by the provider")
        return 0.0

    base = f"License '{candidate.get('license')}' reported by provider (not legal clearance)"
    if pref in ("permissive", "commercial-use-ok"):
        if lic in PERMISSIVE_LICENSES:
            evidence.append(base + "; fits your permissive/commercial preference")
            return 1.0
        evidence.append(base + "; may NOT fit your permissive/commercial preference")
        return 0.3
    evidence.append(base)
    return 1.0


def _format_score(candidate: dict, requirement: dict, evidence: list) -> float:
    wanted = [f.lower() for f in requirement.get("preferred_formats", [])]
    if not wanted:
        return 1.0  # no preference -> don't penalise anyone
    text = f"{candidate.get('title', '')} {candidate.get('description', '')}".lower()
    hits = [f for f in wanted if re.search(rf"\b{re.escape(f)}\b", text)]
    if hits:
        evidence.append(f"Preferred format(s) mentioned in metadata: {hits}")
        return 1.0
    evidence.append(f"Preferred format(s) {wanted} not confirmed in metadata (unverified, not ruled out)")
    return 0.3


def _size_score(candidate: dict, requirement: dict, evidence: list) -> float:
    limit_mb = requirement.get("max_size_mb")
    if not limit_mb:
        return 1.0
    size = candidate.get("size_bytes")
    if not size:
        evidence.append("Size unknown - cannot confirm it fits your limit")
        return 0.5
    size_mb = size / (1024 * 1024)
    if size_mb <= limit_mb:
        evidence.append(f"Size ~{size_mb:.1f} MB is within your {limit_mb} MB limit")
        return 1.0
    evidence.append(f"Size ~{size_mb:.1f} MB exceeds your {limit_mb} MB limit")
    return 0.0


def score_candidate(candidate: dict, requirement: dict) -> dict:
    """Returns a copy of `candidate` with relevance_score and score_breakdown replaced."""
    evidence: list[str] = []
    provider_signals = candidate.get("score_breakdown") or {}

    factors = {
        "topical_relevance": _topical_relevance(candidate, requirement, evidence),
        "resource_type_match": _type_match(candidate, requirement, evidence),
        "license_evidence": _license_score(candidate, requirement, evidence),
        "format_match": _format_score(candidate, requirement, evidence),
        "size_fit": _size_score(candidate, requirement, evidence),
        "popularity_signal": float(provider_signals.get("popularity_signal", 0.0)),
    }
    total = sum(WEIGHTS[name] * value for name, value in factors.items())

    scored = dict(candidate)
    scored["relevance_score"] = round(total, 3)
    scored["score_breakdown"] = {
        "factors": {k: round(v, 2) for k, v in factors.items()},
        "weights": WEIGHTS,
        "evidence": evidence,
    }
    return scored


def rank_candidates(candidates: list[dict], requirement: dict) -> list[dict]:
    """Scores all candidates and returns them best-first."""
    scored = [score_candidate(c, requirement) for c in candidates]
    return sorted(scored, key=lambda c: c["relevance_score"], reverse=True)

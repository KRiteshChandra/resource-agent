"""
requirement_parser.py
----------------------
Parses a natural-language resource request into the structured `Requirement`
fields our connectors and ranking engine expect: resource_types, topics,
preferred_formats, license_preference, max_size_mb.

Design choice (per implementation-plan.md Stage 2, task 2):
We start with a RULE-BASED parser, not an LLM call. Reasons:
  1. No LLM key is required to run Stage 2 end-to-end.
  2. Deterministic parsing is easier to debug and test than an LLM call.
  3. The architecture's core principle is "LLM interprets/explains, backend
     enforces" — this parser can later be swapped for an LLM-assisted
     version (see `parse_with_llm` stub below) WITHOUT changing its
     output contract, since routers only depend on the returned dict shape.
"""

import re

# Keywords that indicate the kind of resource being requested.
RESOURCE_TYPE_KEYWORDS = {
    "dataset": ["dataset", "datasets", "data set", "data"],
    "repository": ["repository", "repositories", "repo", "repos", "codebase", "code"],
    "notebook": ["notebook", "notebooks"],
    "model": ["model", "models", "pretrained model", "checkpoint"],
}

# File formats we recognize explicitly.
FORMAT_KEYWORDS = [
    "csv", "json", "jsonl", "txt", "markdown", "md", "pdf",
    "parquet", "xml", "yaml", "yml", "image", "images", "png", "jpg",
]

# Phrases indicating a license preference, mapped to a normalized category.
LICENSE_PATTERNS = [
    (r"\b(permissive|mit|apache|bsd)\b", "permissive"),
    (r"\bcommercial[- ]use\b", "commercial-use-ok"),
    (r"\bopen[- ]source\b", "permissive"),
    (r"\bany license\b", "any"),
    (r"\bfree to use\b", "permissive"),
]

# Common filler phrases to strip before extracting topic text.
FILLER_PHRASES = [
    "i need", "i want", "i'm looking for", "im looking for", "looking for",
    "find", "search for", "get me", "please find", "can you find",
    "containing", "about", "related to", "regarding", "for",
]

# Stopwords dropped from the remaining topic text token-by-token.
STOPWORDS = {
    "a", "an", "the", "of", "and", "or", "with", "that", "which", "to",
    "in", "on", "datasets", "dataset", "repository", "repositories",
    "repo", "repos", "data", "license", "licence", "allowed", "use",
    "mb", "gb",
}

SIZE_PATTERN = re.compile(
    r"\b(?:under|less than|no more than|max|maximum of)?\s*"
    r"(\d+(?:\.\d+)?)\s*(mb|gb)\b",
    re.IGNORECASE,
)


class RequirementParser:
    """Rule-based parser. Call `.parse(raw_text)` -> dict of Requirement fields."""

    def parse(self, raw_text: str) -> dict:
        text_lower = raw_text.lower()

        resource_types = self._extract_resource_types(text_lower)
        preferred_formats = self._extract_formats(text_lower)
        license_preference = self._extract_license(text_lower)
        max_size_mb = self._extract_size_limit(text_lower)
        topics = self._extract_topics(raw_text)

        return {
            "resource_types": resource_types or ["dataset"],  # sensible default
            "topics": topics,
            "preferred_formats": preferred_formats,
            "license_preference": license_preference,
            "max_size_mb": max_size_mb,
        }

    def _extract_resource_types(self, text_lower: str) -> list[str]:
        found = []
        for canonical, variants in RESOURCE_TYPE_KEYWORDS.items():
            if any(v in text_lower for v in variants):
                found.append(canonical)
        return found

    def _extract_formats(self, text_lower: str) -> list[str]:
        found = []
        for fmt in FORMAT_KEYWORDS:
            # Word-boundary match so "md" doesn't match inside unrelated words.
            if re.search(rf"\b{re.escape(fmt)}\b", text_lower):
                normalized = "markdown" if fmt == "md" else fmt
                if normalized not in found:
                    found.append(normalized)
        return found

    def _extract_license(self, text_lower: str) -> str | None:
        for pattern, category in LICENSE_PATTERNS:
            if re.search(pattern, text_lower):
                return category
        return None

    def _extract_size_limit(self, text_lower: str) -> int | None:
        match = SIZE_PATTERN.search(text_lower)
        if not match:
            return None
        value, unit = match.groups()
        value = float(value)
        if unit.lower() == "gb":
            value *= 1024
        return int(value)

    def _extract_topics(self, raw_text: str) -> list[str]:
        """
        Strips filler phrases and stopwords, then splits remaining text on
        "and"/commas to produce a list of topic phrases. This is intentionally
        simple — good enough to drive connector search queries, not a full
        NLP pipeline.
        """
        text = raw_text.lower()

        # Remove resource-type/format/license/size phrases so they don't leak into topics.
        for fmt in FORMAT_KEYWORDS:
            text = re.sub(rf"\b{re.escape(fmt)}\b", "", text)
        text = SIZE_PATTERN.sub("", text)
        for pattern, _ in LICENSE_PATTERNS:
            text = re.sub(pattern, "", text)

        for phrase in FILLER_PHRASES:
            text = text.replace(phrase, "")

        # Split on common conjunctions/punctuation to get topic phrases.
        parts = re.split(r",| and | or |\.", text)

        topics = []
        for part in parts:
            tokens = [w for w in re.findall(r"[a-zA-Z0-9]+", part) if w not in STOPWORDS]
            phrase = " ".join(tokens).strip()
            if phrase and len(phrase) > 2:
                topics.append(phrase)

        return topics or [raw_text.strip()]  # fallback: use raw text verbatim

    def parse_with_llm(self, raw_text: str) -> dict:
        """
        STUB for Stage 4+: swap in an LLM-assisted parser (e.g. via
        OPENAI_API_KEY) for better handling of ambiguous/complex requests.
        Must return the same dict shape as `parse()` so routers never need
        to change. Not implemented yet — falls back to the rule-based parser.
        """
        return self.parse(raw_text)


if __name__ == "__main__":
    # Quick manual smoke test — run with: python -m app.services.requirement_parser
    parser = RequirementParser()
    examples = [
        "Find datasets containing IT support tickets and resolutions.",
        "I need a repository with React dashboard code, under 50 MB, permissive license.",
        "Looking for a CSV dataset about network security logs and incident resolution, commercial use allowed.",
    ]
    for ex in examples:
        print(ex)
        print(" ->", parser.parse(ex))
        print()

"""
web_search_connector.py
------------------------
STUB for Stage 4. Returns no results until a real provider (e.g. Brave Search
or Tavily) is wired in. Keeping it in the connector list now means adding web
search later needs NO change to the orchestrator, ranking engine or routers.

When you implement it:
  * read the key from BRAVE_SEARCH_API_KEY (or TAVILY_API_KEY) in .env
  * return dicts with the same fields as the other connectors
  * re-check threat-model.md (T1 prompt injection, T3 SSRF) before enabling it
"""

import os


class WebSearchConnector:
    name = "web"

    def __init__(self):
        self.api_key = os.getenv("BRAVE_SEARCH_API_KEY") or os.getenv("TAVILY_API_KEY")

    def search(self, requirement: dict, max_results: int = 5) -> list[dict]:
        # Not implemented in the MVP - always empty, even if a key is present.
        return []

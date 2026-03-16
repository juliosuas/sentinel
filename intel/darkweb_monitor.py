"""Dark web monitoring — searches for mentions of assets via DarkSearch API."""

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Optional

import requests

from core.config import Config

logger = logging.getLogger("sentinel.intel.darkweb")


class DarkWebMonitor:
    """Monitors dark web sources for mentions of specified keywords/domains."""

    DARKSEARCH_API = "https://darksearch.io/api/search"

    def __init__(self, config: Optional[Config] = None,
                 callback: Optional[Callable] = None):
        self.config = config or Config()
        self.callback = callback or (lambda r: logger.info("Dark web hit: %s", r.get("title", "")))
        self._keywords: list[str] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._results: list[dict] = []

    def add_keyword(self, keyword: str):
        """Add a keyword to monitor."""
        if keyword not in self._keywords:
            self._keywords.append(keyword)

    def start(self, interval: int = 3600):
        """Start periodic dark web searches."""
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop, args=(interval,),
            daemon=True, name="darkweb-monitor",
        )
        self._thread.start()
        logger.info("Dark web monitor started (%d keywords)", len(self._keywords))

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def search(self, query: str, page: int = 1) -> list[dict]:
        """Search dark web for a query."""
        try:
            params = {"query": query, "page": page}
            headers = {}
            if self.config.DARKSEARCH_API_KEY:
                headers["Authorization"] = f"Bearer {self.config.DARKSEARCH_API_KEY}"

            resp = requests.get(
                self.DARKSEARCH_API,
                params=params,
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()

            results = []
            for item in data.get("data", []):
                result = {
                    "title": item.get("title", ""),
                    "link": item.get("link", ""),
                    "description": item.get("description", "")[:500],
                    "query": query,
                    "found_at": datetime.now(timezone.utc).isoformat(),
                }
                results.append(result)
            return results
        except Exception:
            logger.exception("Dark web search failed for: %s", query)
            return []

    def search_all(self) -> list[dict]:
        """Search for all monitored keywords."""
        all_results = []
        for keyword in self._keywords:
            results = self.search(keyword)
            all_results.extend(results)
            for r in results:
                self.callback(r)
            # Rate limiting
            time.sleep(2)
        self._results.extend(all_results)
        return all_results

    def get_results(self) -> list[dict]:
        """Get all historical results."""
        return list(self._results)

    def _monitor_loop(self, interval: int):
        self.search_all()
        while self._running:
            for _ in range(interval):
                if not self._running:
                    return
                time.sleep(1)
            self.search_all()

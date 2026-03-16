"""API collector — ingest logs from external APIs (cloud providers, SaaS, etc.)."""

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Optional

import requests

from core.config import Config

logger = logging.getLogger("sentinel.collectors.api")


class APICollector:
    """Collects security events from external REST APIs."""

    def __init__(self, config: Optional[Config] = None, callback: Optional[Callable] = None):
        self.config = config or Config()
        self.callback = callback or (lambda e: None)
        self._running = False
        self._threads: list[threading.Thread] = []
        self._sources: list[dict] = []

    def add_source(self, name: str, url: str, headers: Optional[dict] = None,
                   interval: int = 60, parser: Optional[Callable] = None):
        """Register an API source to poll."""
        self._sources.append({
            "name": name,
            "url": url,
            "headers": headers or {},
            "interval": interval,
            "parser": parser or self._default_parser,
            "last_poll": None,
        })

    def start(self):
        """Start polling all registered API sources."""
        self._running = True
        for source in self._sources:
            t = threading.Thread(
                target=self._poll_source, args=(source,),
                daemon=True, name=f"api-{source['name']}",
            )
            t.start()
            self._threads.append(t)
        logger.info("API collector started (%d sources)", len(self._sources))

    def stop(self):
        """Stop all API polling."""
        self._running = False
        for t in self._threads:
            t.join(timeout=5)
        self._threads.clear()
        logger.info("API collector stopped.")

    def _poll_source(self, source: dict):
        """Poll a single API source on its interval."""
        while self._running:
            try:
                resp = requests.get(
                    source["url"],
                    headers=source["headers"],
                    timeout=30,
                )
                resp.raise_for_status()
                events = source["parser"](resp.json(), source["name"])
                for event in events:
                    self.callback(event)
                source["last_poll"] = datetime.now(timezone.utc).isoformat()
            except Exception:
                logger.exception("API poll failed for %s", source["name"])

            # Sleep in small increments for clean shutdown
            for _ in range(source["interval"]):
                if not self._running:
                    return
                time.sleep(1)

    @staticmethod
    def _default_parser(data: dict, source_name: str) -> list[dict]:
        """Default parser — wraps raw API response as events."""
        now = datetime.now(timezone.utc).isoformat()

        # Handle common API response formats
        items = []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            for key in ("events", "results", "data", "items", "logs", "records"):
                if key in data and isinstance(data[key], list):
                    items = data[key]
                    break
            if not items:
                items = [data]

        events = []
        for item in items:
            event = {
                "timestamp": item.get("timestamp", now),
                "source": f"api:{source_name}",
                "event_type": item.get("type", item.get("event_type", "api_event")),
                "raw": str(item),
                "severity": item.get("severity", "info"),
            }
            # Merge known fields
            for field in ("src_ip", "dst_ip", "user", "username", "hostname",
                          "message", "action", "status"):
                if field in item:
                    event[field] = item[field]
            events.append(event)

        return events

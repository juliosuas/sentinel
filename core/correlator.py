"""Event correlation engine — links related events across time windows."""

import logging
import time
from collections import defaultdict
from typing import Optional

logger = logging.getLogger("sentinel.correlator")


class EventCorrelator:
    """Correlates related security events across configurable time windows."""

    def __init__(self, window: int = 300, max_events: int = 10000):
        self.window = window  # correlation window in seconds
        self.max_events = max_events

        # Indexed event stores
        self._events: list[dict] = []
        self._by_ip: dict[str, list[int]] = defaultdict(list)  # ip -> [event indices]
        self._by_user: dict[str, list[int]] = defaultdict(list)
        self._by_host: dict[str, list[int]] = defaultdict(list)
        self._by_session: dict[str, list[int]] = defaultdict(list)

    def correlate(self, event: dict) -> list[dict]:
        """Add an event and return correlated events within the time window."""
        now = time.time()
        self._prune(now)

        idx = len(self._events)
        event["_corr_time"] = now
        self._events.append(event)

        # Index by key fields
        for ip_field in ("src_ip", "dst_ip"):
            ip = event.get(ip_field)
            if ip:
                self._by_ip[ip].append(idx)

        user = event.get("user") or event.get("username")
        if user:
            self._by_user[user].append(idx)

        host = event.get("hostname") or event.get("host")
        if host:
            self._by_host[host].append(idx)

        session = event.get("session_id")
        if session:
            self._by_session[session].append(idx)

        # Find correlated events
        correlated_indices = set()

        for ip_field in ("src_ip", "dst_ip"):
            ip = event.get(ip_field)
            if ip:
                for i in self._by_ip.get(ip, []):
                    if i != idx:
                        correlated_indices.add(i)

        if user:
            for i in self._by_user.get(user, []):
                if i != idx:
                    correlated_indices.add(i)

        if session:
            for i in self._by_session.get(session, []):
                if i != idx:
                    correlated_indices.add(i)

        # Return correlated events (most recent first), limit to 50
        correlated = []
        for i in sorted(correlated_indices, reverse=True)[:50]:
            if i < len(self._events):
                e = self._events[i].copy()
                e.pop("_corr_time", None)
                correlated.append(e)

        return correlated

    def _prune(self, now: float):
        """Remove events outside the correlation window."""
        if len(self._events) <= self.max_events:
            return

        cutoff = now - self.window
        # Find first event within window
        first_valid = 0
        for i, e in enumerate(self._events):
            if e.get("_corr_time", 0) >= cutoff:
                first_valid = i
                break
        else:
            first_valid = len(self._events)

        if first_valid > 0:
            self._events = self._events[first_valid:]
            # Rebuild indices
            self._by_ip.clear()
            self._by_user.clear()
            self._by_host.clear()
            self._by_session.clear()
            for idx, event in enumerate(self._events):
                for ip_field in ("src_ip", "dst_ip"):
                    ip = event.get(ip_field)
                    if ip:
                        self._by_ip[ip].append(idx)
                user = event.get("user") or event.get("username")
                if user:
                    self._by_user[user].append(idx)
                host = event.get("hostname") or event.get("host")
                if host:
                    self._by_host[host].append(idx)
                session = event.get("session_id")
                if session:
                    self._by_session[session].append(idx)

    def get_chain(self, ip: str) -> list[dict]:
        """Get the full event chain for an IP address."""
        events = []
        for i in self._by_ip.get(ip, []):
            if i < len(self._events):
                e = self._events[i].copy()
                e.pop("_corr_time", None)
                events.append(e)
        return events

    def get_user_activity(self, user: str) -> list[dict]:
        """Get all correlated activity for a user."""
        events = []
        for i in self._by_user.get(user, []):
            if i < len(self._events):
                e = self._events[i].copy()
                e.pop("_corr_time", None)
                events.append(e)
        return events

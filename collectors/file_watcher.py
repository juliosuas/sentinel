"""File watcher — monitors log files for changes using watchdog."""

import logging
import re
import os
from datetime import datetime, timezone
from typing import Callable, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

from core.config import Config

logger = logging.getLogger("sentinel.collectors.file_watcher")

# Common log patterns
LOG_PATTERNS = {
    "auth": re.compile(
        r"(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)"
    ),
    "apache_access": re.compile(
        r'(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)'
    ),
    "nginx_access": re.compile(
        r'(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)'
    ),
}


class LogFileHandler(FileSystemEventHandler):
    """Handles file change events from watchdog."""

    def __init__(self, callback: Callable, path: str):
        self.callback = callback
        self.path = path
        self._positions: dict[str, int] = {}

    def on_modified(self, event):
        if isinstance(event, FileModifiedEvent) and not event.is_directory:
            self._read_new_lines(event.src_path)

    def _read_new_lines(self, filepath: str):
        """Read only new lines appended since last check."""
        try:
            size = os.path.getsize(filepath)
            last_pos = self._positions.get(filepath, 0)

            # Handle log rotation (file got smaller)
            if size < last_pos:
                last_pos = 0

            if size == last_pos:
                return

            with open(filepath, "r", errors="replace") as f:
                f.seek(last_pos)
                for line in f:
                    line = line.strip()
                    if line:
                        event = self._parse_line(line, filepath)
                        self.callback(event)
                self._positions[filepath] = f.tell()
        except Exception:
            logger.exception("Error reading %s", filepath)

    def _parse_line(self, line: str, filepath: str) -> dict:
        """Parse a log line into a structured event."""
        basename = os.path.basename(filepath).lower()
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": f"file:{filepath}",
            "raw": line,
            "event_type": "log_line",
        }

        # Try auth log pattern
        if "auth" in basename or "secure" in basename:
            m = LOG_PATTERNS["auth"].match(line)
            if m:
                event["syslog_timestamp"] = m.group(1)
                event["hostname"] = m.group(2)
                event["program"] = m.group(3)
                event["pid"] = m.group(4)
                event["message"] = m.group(5)
                event["event_type"] = "auth"
                self._enrich_auth(event)
                return event

        # Try apache/nginx access log
        if "access" in basename:
            for name in ("apache_access", "nginx_access"):
                m = LOG_PATTERNS[name].match(line)
                if m:
                    event["src_ip"] = m.group(1)
                    event["user"] = m.group(2) if m.group(2) != "-" else None
                    event["method"] = m.group(4)
                    event["path"] = m.group(5)
                    event["status_code"] = int(m.group(6))
                    event["bytes"] = int(m.group(7))
                    event["event_type"] = "web_access"
                    return event

        return event

    def _enrich_auth(self, event: dict):
        """Enrich auth log events with parsed fields."""
        msg = event.get("message", "")

        if "Failed password" in msg:
            event["event_type"] = "auth_failure"
            m = re.search(r"from (\S+)", msg)
            if m:
                event["src_ip"] = m.group(1)
            m = re.search(r"for (?:invalid user )?(\S+)", msg)
            if m:
                event["username"] = m.group(1)

        elif "Accepted" in msg:
            event["event_type"] = "auth_success"
            m = re.search(r"from (\S+)", msg)
            if m:
                event["src_ip"] = m.group(1)
            m = re.search(r"for (\S+)", msg)
            if m:
                event["username"] = m.group(1)

        elif "sudo" in msg.lower():
            event["event_type"] = "sudo"

        elif "useradd" in msg or "new user" in msg.lower():
            event["event_type"] = "user_add"


class FileWatcher:
    """Watches multiple log files for changes."""

    def __init__(self, config: Optional[Config] = None, callback: Optional[Callable] = None):
        self.config = config or Config()
        self.callback = callback or (lambda e: logger.debug("Event: %s", e.get("event_type")))
        self._observer = Observer()
        self._handlers: list[LogFileHandler] = []

    def start(self):
        """Start watching configured log file paths."""
        for path in self.config.WATCH_PATHS:
            path = path.strip()
            if not path:
                continue

            if os.path.isfile(path):
                directory = os.path.dirname(path)
                handler = LogFileHandler(self.callback, path)
                self._handlers.append(handler)
                self._observer.schedule(handler, directory, recursive=False)
                logger.info("Watching file: %s", path)
            elif os.path.isdir(path):
                handler = LogFileHandler(self.callback, path)
                self._handlers.append(handler)
                self._observer.schedule(handler, path, recursive=True)
                logger.info("Watching directory: %s", path)
            else:
                logger.warning("Path not found, skipping: %s", path)

        self._observer.start()
        logger.info("File watcher started (%d paths)", len(self._handlers))

    def stop(self):
        """Stop watching files."""
        self._observer.stop()
        self._observer.join(timeout=5)
        logger.info("File watcher stopped.")

    def add_path(self, path: str):
        """Dynamically add a path to watch."""
        if os.path.exists(path):
            directory = os.path.dirname(path) if os.path.isfile(path) else path
            handler = LogFileHandler(self.callback, path)
            self._handlers.append(handler)
            self._observer.schedule(handler, directory, recursive=os.path.isdir(path))
            logger.info("Added watch path: %s", path)

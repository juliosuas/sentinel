"""Syslog collector — receives logs via UDP and TCP."""

import logging
import re
import socket
import socketserver
import threading
from datetime import datetime, timezone
from typing import Callable, Optional

from core.config import Config

logger = logging.getLogger("sentinel.collectors.syslog")

# RFC 3164 syslog pattern
SYSLOG_PATTERN = re.compile(
    r"<(\d+)>"
    r"(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(\S+)\s+"
    r"(\S+?)(?:\[(\d+)\])?:\s+"
    r"(.*)"
)

# Auth-related patterns for enrichment
AUTH_PATTERNS = {
    "ssh_failed": re.compile(
        r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)"
    ),
    "ssh_success": re.compile(
        r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)"
    ),
    "sudo": re.compile(r"(\S+)\s*:.*COMMAND=(.*)"),
    "su": re.compile(r"su:\s+\S+\s+(\S+)-(\S+)"),
    "user_add": re.compile(r"new user: name=(\S+)"),
    "crontab": re.compile(r"crontab\[(\d+)\].*\((\S+)\)\s+(REPLACE|DELETE|LIST)"),
}


def parse_syslog(data: str) -> Optional[dict]:
    """Parse a syslog message into a structured event."""
    match = SYSLOG_PATTERN.match(data.strip())
    if not match:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "syslog",
            "raw": data.strip(),
            "event_type": "unknown",
        }

    priority = int(match.group(1))
    facility = priority >> 3
    severity_num = priority & 0x07
    severity_map = {0: "critical", 1: "critical", 2: "critical", 3: "high",
                    4: "medium", 5: "medium", 6: "low", 7: "info"}

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "syslog_timestamp": match.group(2),
        "hostname": match.group(3),
        "program": match.group(4),
        "pid": match.group(5),
        "message": match.group(6),
        "raw": data.strip(),
        "source": "syslog",
        "facility": facility,
        "severity": severity_map.get(severity_num, "info"),
        "event_type": "syslog",
    }

    # Enrich with auth pattern matching
    message = event["message"]
    for event_type, pattern in AUTH_PATTERNS.items():
        m = pattern.search(message)
        if m:
            event["event_type"] = event_type
            groups = m.groups()
            if event_type == "ssh_failed":
                event["username"] = groups[0]
                event["src_ip"] = groups[1]
                event["src_port"] = int(groups[2])
            elif event_type == "ssh_success":
                event["username"] = groups[0]
                event["src_ip"] = groups[1]
                event["src_port"] = int(groups[2])
            elif event_type == "sudo":
                event["username"] = groups[0]
                event["command"] = groups[1].strip()
            elif event_type == "user_add":
                event["new_user"] = groups[0]
            elif event_type == "crontab":
                event["username"] = groups[1]
                event["crontab_action"] = groups[2]
            break

    return event


class UDPSyslogHandler(socketserver.BaseRequestHandler):
    """Handle incoming UDP syslog messages."""

    def handle(self):
        data = self.request[0].decode("utf-8", errors="replace")
        event = parse_syslog(data)
        if event and hasattr(self.server, "callback"):
            self.server.callback(event)


class TCPSyslogHandler(socketserver.StreamRequestHandler):
    """Handle incoming TCP syslog messages."""

    def handle(self):
        while True:
            try:
                line = self.rfile.readline()
                if not line:
                    break
                data = line.decode("utf-8", errors="replace")
                event = parse_syslog(data)
                if event and hasattr(self.server, "callback"):
                    self.server.callback(event)
            except Exception:
                break


class SyslogCollector:
    """Collects syslog messages via UDP and TCP."""

    def __init__(self, config: Optional[Config] = None, callback: Optional[Callable] = None):
        self.config = config or Config()
        self.callback = callback or (lambda e: logger.debug("Event: %s", e.get("event_type")))
        self._servers: list = []
        self._threads: list[threading.Thread] = []

    def start(self):
        """Start UDP and TCP syslog listeners."""
        # UDP
        udp_server = socketserver.UDPServer(
            (self.config.SYSLOG_HOST, self.config.SYSLOG_UDP_PORT),
            UDPSyslogHandler,
        )
        udp_server.callback = self.callback
        self._servers.append(udp_server)
        t = threading.Thread(target=udp_server.serve_forever, daemon=True, name="syslog-udp")
        t.start()
        self._threads.append(t)
        logger.info("Syslog UDP listener started on %s:%d",
                     self.config.SYSLOG_HOST, self.config.SYSLOG_UDP_PORT)

        # TCP
        tcp_server = socketserver.TCPServer(
            (self.config.SYSLOG_HOST, self.config.SYSLOG_TCP_PORT),
            TCPSyslogHandler,
        )
        tcp_server.callback = self.callback
        self._servers.append(tcp_server)
        t = threading.Thread(target=tcp_server.serve_forever, daemon=True, name="syslog-tcp")
        t.start()
        self._threads.append(t)
        logger.info("Syslog TCP listener started on %s:%d",
                     self.config.SYSLOG_HOST, self.config.SYSLOG_TCP_PORT)

    def stop(self):
        """Stop all syslog listeners."""
        for server in self._servers:
            server.shutdown()
        self._servers.clear()
        self._threads.clear()
        logger.info("Syslog collectors stopped.")

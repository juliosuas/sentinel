"""Network traffic monitor — pcap-based packet capture and analysis."""

import logging
import threading
from datetime import datetime, timezone
from typing import Callable, Optional

from core.config import Config

logger = logging.getLogger("sentinel.collectors.network")


class NetworkMonitor:
    """Captures and analyzes network traffic using scapy."""

    def __init__(self, config: Optional[Config] = None, callback: Optional[Callable] = None):
        self.config = config or Config()
        self.callback = callback or (lambda e: logger.debug("Packet: %s", e.get("event_type")))
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Start packet capture on configured interface."""
        self._running = True
        self._thread = threading.Thread(target=self._capture, daemon=True, name="network-monitor")
        self._thread.start()
        logger.info("Network monitor started on %s", self.config.NETWORK_INTERFACE)

    def stop(self):
        """Stop packet capture."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Network monitor stopped.")

    def _capture(self):
        """Main capture loop using scapy."""
        try:
            from scapy.all import sniff, IP, TCP, UDP, DNS
        except ImportError:
            logger.error("scapy not available — network monitoring disabled")
            return

        def process_packet(pkt):
            if not self._running:
                return

            if not pkt.haslayer(IP):
                return

            ip = pkt[IP]
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "network",
                "event_type": "network",
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "protocol": ip.proto,
                "ttl": ip.ttl,
                "length": len(pkt),
            }

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                event["src_port"] = tcp.sport
                event["dst_port"] = tcp.dport
                event["tcp_flags"] = str(tcp.flags)

                # Detect SYN scan
                if tcp.flags == "S":
                    event["event_type"] = "connection"

                # Detect data transfer
                payload_len = len(tcp.payload)
                if payload_len > 0:
                    event["bytes_sent"] = payload_len
                    # Heuristic: outbound if src is private
                    if self._is_private(ip.src):
                        event["direction"] = "outbound"
                    else:
                        event["direction"] = "inbound"

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                event["src_port"] = udp.sport
                event["dst_port"] = udp.dport

                if pkt.haslayer(DNS):
                    dns = pkt[DNS]
                    if dns.qr == 0 and dns.qd:  # DNS query
                        event["event_type"] = "dns_query"
                        event["dns_query"] = dns.qd.qname.decode("utf-8", errors="replace")

            self.callback(event)

        try:
            sniff(
                iface=self.config.NETWORK_INTERFACE,
                prn=process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            logger.error("Permission denied for packet capture — run as root or with CAP_NET_RAW")
        except Exception:
            logger.exception("Network capture error")

    @staticmethod
    def _is_private(ip: str) -> bool:
        """Check if an IP is in a private range."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        first, second = int(parts[0]), int(parts[1])
        return (
            first == 10
            or (first == 172 and 16 <= second <= 31)
            or (first == 192 and second == 168)
            or first == 127
        )

"""Threat intelligence feed aggregator — AbuseIPDB, AlienVault OTX, and more."""

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import requests

from core.config import Config

logger = logging.getLogger("sentinel.intel.feeds")


class ThreatFeedManager:
    """Aggregates threat intelligence from multiple free feeds."""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self._malicious_ips: set[str] = set()
        self._malicious_domains: set[str] = set()
        self._threat_data: dict[str, dict] = {}  # ip/domain -> details
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_update: Optional[str] = None

    @property
    def malicious_ips(self) -> set[str]:
        return set(self._malicious_ips)

    @property
    def malicious_domains(self) -> set[str]:
        return set(self._malicious_domains)

    def start(self, interval: int = 3600):
        """Start periodic feed updates."""
        self._running = True
        self._thread = threading.Thread(
            target=self._update_loop, args=(interval,),
            daemon=True, name="threat-feeds",
        )
        self._thread.start()
        logger.info("Threat feed manager started (interval: %ds)", interval)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def update_all(self):
        """Pull from all configured feeds."""
        logger.info("Updating threat intelligence feeds...")
        self._fetch_abuseipdb()
        self._fetch_otx()
        self._fetch_emergingthreats()
        self._last_update = datetime.now(timezone.utc).isoformat()
        logger.info(
            "Threat feeds updated: %d IPs, %d domains",
            len(self._malicious_ips), len(self._malicious_domains),
        )

    def check_ip(self, ip: str) -> Optional[dict]:
        """Check if an IP is in threat feeds."""
        if ip in self._malicious_ips:
            return self._threat_data.get(ip, {"ip": ip, "malicious": True})
        return None

    def check_domain(self, domain: str) -> Optional[dict]:
        """Check if a domain is in threat feeds."""
        domain = domain.lower().rstrip(".")
        if domain in self._malicious_domains:
            return self._threat_data.get(domain, {"domain": domain, "malicious": True})
        # Check subdomains
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._malicious_domains:
                return self._threat_data.get(parent, {"domain": parent, "malicious": True})
        return None

    def get_stats(self) -> dict:
        return {
            "malicious_ips": len(self._malicious_ips),
            "malicious_domains": len(self._malicious_domains),
            "last_update": self._last_update,
        }

    def _update_loop(self, interval: int):
        self.update_all()
        while self._running:
            for _ in range(interval):
                if not self._running:
                    return
                time.sleep(1)
            self.update_all()

    def _fetch_abuseipdb(self):
        """Fetch blacklisted IPs from AbuseIPDB."""
        if not self.config.ABUSEIPDB_API_KEY:
            return
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/blacklist",
                headers={
                    "Key": self.config.ABUSEIPDB_API_KEY,
                    "Accept": "application/json",
                },
                params={"confidenceMinimum": 90, "limit": 1000},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json().get("data", [])
            for entry in data:
                ip = entry.get("ipAddress")
                if ip:
                    self._malicious_ips.add(ip)
                    self._threat_data[ip] = {
                        "ip": ip,
                        "source": "abuseipdb",
                        "confidence": entry.get("abuseConfidenceScore", 0),
                        "country": entry.get("countryCode", ""),
                    }
            logger.info("AbuseIPDB: loaded %d IPs", len(data))
        except Exception:
            logger.exception("AbuseIPDB feed failed")

    def _fetch_otx(self):
        """Fetch indicators from AlienVault OTX."""
        if not self.config.OTX_API_KEY:
            return
        try:
            resp = requests.get(
                "https://otx.alienvault.com/api/v1/pulses/subscribed",
                headers={"X-OTX-API-KEY": self.config.OTX_API_KEY},
                params={"limit": 50, "modified_since": ""},
                timeout=30,
            )
            resp.raise_for_status()
            pulses = resp.json().get("results", [])
            ip_count = 0
            domain_count = 0
            for pulse in pulses:
                for indicator in pulse.get("indicators", []):
                    ioc_type = indicator.get("type", "")
                    value = indicator.get("indicator", "")
                    if ioc_type in ("IPv4", "IPv6"):
                        self._malicious_ips.add(value)
                        self._threat_data[value] = {
                            "ip": value,
                            "source": "otx",
                            "pulse": pulse.get("name", ""),
                        }
                        ip_count += 1
                    elif ioc_type in ("domain", "hostname"):
                        self._malicious_domains.add(value.lower())
                        self._threat_data[value.lower()] = {
                            "domain": value,
                            "source": "otx",
                            "pulse": pulse.get("name", ""),
                        }
                        domain_count += 1
            logger.info("OTX: loaded %d IPs, %d domains", ip_count, domain_count)
        except Exception:
            logger.exception("OTX feed failed")

    def _fetch_emergingthreats(self):
        """Fetch IPs from Emerging Threats (free, no API key)."""
        try:
            resp = requests.get(
                "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                timeout=30,
            )
            resp.raise_for_status()
            count = 0
            for line in resp.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    self._malicious_ips.add(line)
                    self._threat_data[line] = {"ip": line, "source": "emergingthreats"}
                    count += 1
            logger.info("EmergingThreats: loaded %d IPs", count)
        except Exception:
            logger.exception("EmergingThreats feed failed")

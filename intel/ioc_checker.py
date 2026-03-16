"""IOC (Indicators of Compromise) checker — validates IOCs against threat feeds."""

import hashlib
import logging
import re
from typing import Optional

import requests

from core.config import Config
from intel.threat_feeds import ThreatFeedManager

logger = logging.getLogger("sentinel.intel.ioc")

# Patterns for IOC extraction
IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "url": re.compile(r"https?://[^\s<>\"']+"),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
}


class IOCChecker:
    """Checks indicators of compromise against multiple sources."""

    def __init__(self, config: Optional[Config] = None,
                 feed_manager: Optional[ThreatFeedManager] = None):
        self.config = config or Config()
        self.feeds = feed_manager or ThreatFeedManager(self.config)

    def check(self, indicator: str, ioc_type: Optional[str] = None) -> dict:
        """Check a single IOC against all available sources."""
        if not ioc_type:
            ioc_type = self._detect_type(indicator)

        result = {
            "indicator": indicator,
            "type": ioc_type,
            "malicious": False,
            "sources": [],
            "details": {},
        }

        if ioc_type == "ipv4":
            feed_result = self.feeds.check_ip(indicator)
            if feed_result:
                result["malicious"] = True
                result["sources"].append(feed_result.get("source", "feed"))
                result["details"]["feed"] = feed_result

            # Check AbuseIPDB for detailed info
            abuseipdb = self._check_abuseipdb(indicator)
            if abuseipdb:
                result["details"]["abuseipdb"] = abuseipdb
                if abuseipdb.get("abuseConfidenceScore", 0) > 50:
                    result["malicious"] = True
                    if "abuseipdb" not in result["sources"]:
                        result["sources"].append("abuseipdb")

        elif ioc_type == "domain":
            feed_result = self.feeds.check_domain(indicator)
            if feed_result:
                result["malicious"] = True
                result["sources"].append(feed_result.get("source", "feed"))
                result["details"]["feed"] = feed_result

        elif ioc_type in ("md5", "sha1", "sha256"):
            # Could integrate with VirusTotal, MalwareBazaar, etc.
            result["details"]["note"] = "Hash checking requires VirusTotal API"

        return result

    def check_event(self, event: dict) -> list[dict]:
        """Extract and check all IOCs from an event."""
        results = []
        raw = event.get("raw", "")

        # Check specific fields first
        for field in ("src_ip", "dst_ip"):
            ip = event.get(field)
            if ip:
                result = self.check(ip, "ipv4")
                if result["malicious"]:
                    results.append(result)

        # Check DNS queries
        dns = event.get("dns_query", "")
        if dns:
            result = self.check(dns.rstrip("."), "domain")
            if result["malicious"]:
                results.append(result)

        # Extract IOCs from raw log
        for ioc_type, pattern in IOC_PATTERNS.items():
            if ioc_type in ("ipv4", "domain"):
                for match in pattern.finditer(raw):
                    indicator = match.group()
                    # Skip private IPs
                    if ioc_type == "ipv4" and self._is_private(indicator):
                        continue
                    result = self.check(indicator, ioc_type)
                    if result["malicious"]:
                        results.append(result)

        return results

    def extract_iocs(self, text: str) -> dict[str, list[str]]:
        """Extract all IOCs from a text string."""
        extracted = {}
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = list(set(pattern.findall(text)))
            if matches:
                extracted[ioc_type] = matches
        return extracted

    def _check_abuseipdb(self, ip: str) -> Optional[dict]:
        """Check a single IP against AbuseIPDB."""
        if not self.config.ABUSEIPDB_API_KEY:
            return None
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": self.config.ABUSEIPDB_API_KEY,
                    "Accept": "application/json",
                },
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json().get("data")
        except Exception:
            logger.exception("AbuseIPDB check failed for %s", ip)
            return None

    @staticmethod
    def _detect_type(indicator: str) -> str:
        """Auto-detect the type of an IOC."""
        for ioc_type, pattern in IOC_PATTERNS.items():
            if pattern.fullmatch(indicator):
                return ioc_type
        return "unknown"

    @staticmethod
    def _is_private(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            first, second = int(parts[0]), int(parts[1])
        except ValueError:
            return False
        return (
            first == 10
            or (first == 172 and 16 <= second <= 31)
            or (first == 192 and second == 168)
            or first == 127
        )

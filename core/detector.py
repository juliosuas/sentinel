"""Anomaly detection module — statistical and behavioral threat detection."""

import logging
import time
from collections import defaultdict
from typing import Optional

import numpy as np

from core.config import Config

logger = logging.getLogger("sentinel.detector")


class AnomalyDetector:
    """Multi-method anomaly detection for security events."""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()

        # Behavioral baselines: {metric_key: [values]}
        self._baselines: dict[str, list[float]] = defaultdict(list)
        self._baseline_max = 1000  # max data points per metric

        # Tracking state for pattern detectors
        self._login_attempts: dict[str, list[float]] = defaultdict(list)  # ip -> [timestamps]
        self._port_access: dict[str, set[int]] = defaultdict(set)  # ip -> {ports}
        self._port_access_times: dict[str, float] = defaultdict(float)
        self._transfer_sizes: dict[str, list[float]] = defaultdict(list)  # ip -> [bytes]
        self._priv_events: dict[str, list[float]] = defaultdict(list)  # user -> [timestamps]

    def analyze(self, event: dict) -> list[dict]:
        """Run all detectors on an event. Returns list of anomaly dicts."""
        anomalies = []
        for detector in [
            self._detect_brute_force,
            self._detect_port_scan,
            self._detect_exfiltration,
            self._detect_privilege_escalation,
            self._detect_statistical_anomaly,
        ]:
            try:
                result = detector(event)
                if result:
                    anomalies.append(result)
            except Exception:
                logger.exception("Detector %s failed", detector.__name__)
        return anomalies

    def _detect_brute_force(self, event: dict) -> Optional[dict]:
        """Detect brute force login attempts from a single IP."""
        if event.get("event_type") not in ("auth_failure", "login_failed", "ssh_failed"):
            return None

        src_ip = event.get("src_ip", "")
        if not src_ip:
            return None

        now = time.time()
        window = self.config.BRUTE_FORCE_WINDOW
        threshold = self.config.BRUTE_FORCE_THRESHOLD

        self._login_attempts[src_ip].append(now)
        # Prune old entries
        self._login_attempts[src_ip] = [
            t for t in self._login_attempts[src_ip] if now - t < window
        ]

        count = len(self._login_attempts[src_ip])
        if count >= threshold:
            return {
                "type": "brute_force",
                "name": "Brute Force Attack Detected",
                "severity": "high" if count >= threshold * 2 else "medium",
                "description": (
                    f"IP {src_ip} has {count} failed login attempts "
                    f"in the last {window}s (threshold: {threshold})"
                ),
                "src_ip": src_ip,
                "count": count,
            }
        return None

    def _detect_port_scan(self, event: dict) -> Optional[dict]:
        """Detect port scanning activity."""
        if event.get("event_type") not in ("connection", "network", "firewall"):
            return None

        src_ip = event.get("src_ip", "")
        dst_port = event.get("dst_port")
        if not src_ip or dst_port is None:
            return None

        now = time.time()
        window = self.config.PORT_SCAN_WINDOW
        threshold = self.config.PORT_SCAN_THRESHOLD

        # Reset if outside window
        if now - self._port_access_times.get(src_ip, 0) > window:
            self._port_access[src_ip] = set()
        self._port_access_times[src_ip] = now

        self._port_access[src_ip].add(int(dst_port))
        port_count = len(self._port_access[src_ip])

        if port_count >= threshold:
            return {
                "type": "port_scan",
                "name": "Port Scan Detected",
                "severity": "high" if port_count >= threshold * 2 else "medium",
                "description": (
                    f"IP {src_ip} probed {port_count} unique ports "
                    f"in the last {window}s (threshold: {threshold})"
                ),
                "src_ip": src_ip,
                "ports_scanned": port_count,
            }
        return None

    def _detect_exfiltration(self, event: dict) -> Optional[dict]:
        """Detect potential data exfiltration via large outbound transfers."""
        if event.get("event_type") not in ("network", "transfer", "connection"):
            return None

        direction = event.get("direction", "")
        bytes_sent = event.get("bytes_sent", 0) or event.get("bytes", 0)
        if direction != "outbound" or not bytes_sent:
            return None

        src_ip = event.get("src_ip", "")
        threshold_bytes = self.config.EXFIL_THRESHOLD_MB * 1024 * 1024

        self._transfer_sizes[src_ip].append(float(bytes_sent))
        # Keep last 100 entries
        self._transfer_sizes[src_ip] = self._transfer_sizes[src_ip][-100:]

        total = sum(self._transfer_sizes[src_ip])
        if total >= threshold_bytes:
            mb = total / (1024 * 1024)
            return {
                "type": "exfiltration",
                "name": "Potential Data Exfiltration",
                "severity": "critical" if mb > self.config.EXFIL_THRESHOLD_MB * 3 else "high",
                "description": (
                    f"Host {src_ip} transferred {mb:.1f}MB outbound "
                    f"(threshold: {self.config.EXFIL_THRESHOLD_MB}MB)"
                ),
                "src_ip": src_ip,
                "total_bytes": total,
            }
        return None

    def _detect_privilege_escalation(self, event: dict) -> Optional[dict]:
        """Detect privilege escalation attempts."""
        priv_keywords = ("sudo", "su ", "pkexec", "doas", "setuid", "chmod +s", "chown root")
        raw = event.get("raw", "").lower()
        event_type = event.get("event_type", "")

        is_priv_event = event_type in ("privilege_escalation", "sudo", "su") or any(
            kw in raw for kw in priv_keywords
        )
        if not is_priv_event:
            return None

        user = event.get("user", event.get("username", "unknown"))
        now = time.time()
        self._priv_events[user].append(now)
        self._priv_events[user] = [t for t in self._priv_events[user] if now - t < 300]

        count = len(self._priv_events[user])
        if count >= 3:
            return {
                "type": "privilege_escalation",
                "name": "Privilege Escalation Attempt",
                "severity": "critical" if count >= 5 else "high",
                "description": (
                    f"User '{user}' has {count} privilege escalation events "
                    f"in the last 300s"
                ),
                "user": user,
                "count": count,
            }

        # Single suspicious event still worth flagging if it looks like exploitation
        exploit_patterns = ("buffer overflow", "stack smash", "segfault", "exploit", "shellcode")
        if any(p in raw for p in exploit_patterns):
            return {
                "type": "privilege_escalation",
                "name": "Potential Exploit Detected",
                "severity": "critical",
                "description": f"Possible exploitation attempt by user '{user}': {raw[:200]}",
                "user": user,
            }
        return None

    def _detect_statistical_anomaly(self, event: dict) -> Optional[dict]:
        """Detect statistical anomalies using z-score analysis."""
        # Track event rate per source
        src = event.get("source", "unknown")
        now = time.time()

        key = f"rate_{src}"
        self._baselines[key].append(now)
        self._baselines[key] = self._baselines[key][-self._baseline_max:]

        # Need at least 30 data points for meaningful statistics
        timestamps = self._baselines[key]
        if len(timestamps) < 30:
            return None

        # Calculate inter-event intervals
        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        if not intervals:
            return None

        arr = np.array(intervals)
        mean = np.mean(arr)
        std = np.std(arr)

        if std == 0:
            return None

        # Check if the latest interval is anomalous
        latest = intervals[-1]
        z_score = abs(latest - mean) / std

        if z_score >= self.config.ANOMALY_ZSCORE_THRESHOLD:
            # Also check IQR for confirmation
            q1, q3 = np.percentile(arr, [25, 75])
            iqr = q3 - q1
            lower = q1 - 1.5 * iqr
            upper = q3 + 1.5 * iqr
            is_iqr_outlier = latest < lower or latest > upper

            if is_iqr_outlier:
                direction = "spike" if latest < mean else "drop"
                return {
                    "type": "statistical_anomaly",
                    "name": f"Statistical Anomaly — Event Rate {direction.title()}",
                    "severity": "medium" if z_score < 4 else "high",
                    "description": (
                        f"Source '{src}' event rate {direction}: "
                        f"z-score={z_score:.2f}, interval={latest:.2f}s "
                        f"(mean={mean:.2f}s, std={std:.2f}s)"
                    ),
                    "z_score": float(z_score),
                    "source": src,
                }
        return None

    def update_baseline(self, metric: str, value: float):
        """Manually update a behavioral baseline metric."""
        self._baselines[metric].append(value)
        if len(self._baselines[metric]) > self._baseline_max:
            self._baselines[metric] = self._baselines[metric][-self._baseline_max:]

    def get_baseline_stats(self, metric: str) -> Optional[dict]:
        """Get current statistics for a baseline metric."""
        values = self._baselines.get(metric, [])
        if not values:
            return None
        arr = np.array(values)
        return {
            "metric": metric,
            "count": len(values),
            "mean": float(np.mean(arr)),
            "std": float(np.std(arr)),
            "min": float(np.min(arr)),
            "max": float(np.max(arr)),
            "p95": float(np.percentile(arr, 95)),
        }

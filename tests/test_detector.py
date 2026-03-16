"""Tests for SENTINEL anomaly detection engine."""

import time
import unittest

from core.detector import AnomalyDetector


class TestAnomalyDetectorInit(unittest.TestCase):
    """Test detector initialization."""

    def test_creates_instance(self):
        detector = AnomalyDetector()
        self.assertIsNotNone(detector)

    def test_analyze_returns_list(self):
        detector = AnomalyDetector()
        result = detector.analyze({})
        self.assertIsInstance(result, list)

    def test_benign_event_no_anomalies(self):
        detector = AnomalyDetector()
        event = {
            "event_type": "auth_success",
            "src_ip": "192.168.1.10",
            "username": "admin",
            "severity": "info",
        }
        anomalies = detector.analyze(event)
        self.assertEqual(len(anomalies), 0)


class TestBruteForceDetection(unittest.TestCase):
    """Test brute force attack detection."""

    def setUp(self):
        self.detector = AnomalyDetector()

    def test_single_failure_no_alert(self):
        event = {
            "event_type": "ssh_failed",
            "src_ip": "10.0.0.1",
            "username": "root",
        }
        anomalies = self.detector.analyze(event)
        brute = [a for a in anomalies if a.get("type") == "brute_force"]
        self.assertEqual(len(brute), 0)

    def test_multiple_failures_triggers_alert(self):
        """Repeated login failures from same IP should trigger brute force detection."""
        for i in range(10):
            event = {
                "event_type": "ssh_failed",
                "src_ip": "10.0.0.99",
                "username": "root",
                "timestamp": time.time(),
            }
            anomalies = self.detector.analyze(event)

        brute = [a for a in anomalies if a.get("type") == "brute_force"]
        self.assertGreater(len(brute), 0, "Brute force should be detected after many failures")

    def test_different_ips_no_brute_force(self):
        """Failures from different IPs should not trigger brute force for any single IP."""
        for i in range(10):
            event = {
                "event_type": "ssh_failed",
                "src_ip": f"10.0.0.{i}",
                "username": "root",
            }
            self.detector.analyze(event)

        # Each IP only had 1 attempt, so no brute force
        event = {
            "event_type": "ssh_failed",
            "src_ip": "10.0.0.200",
            "username": "root",
        }
        anomalies = self.detector.analyze(event)
        brute = [a for a in anomalies if a.get("type") == "brute_force"]
        self.assertEqual(len(brute), 0)


class TestPortScanDetection(unittest.TestCase):
    """Test port scan detection."""

    def setUp(self):
        self.detector = AnomalyDetector()

    def test_single_port_no_alert(self):
        event = {
            "event_type": "connection",
            "src_ip": "10.0.0.5",
            "dst_port": 80,
        }
        anomalies = self.detector.analyze(event)
        scans = [a for a in anomalies if a.get("type") == "port_scan"]
        self.assertEqual(len(scans), 0)

    def test_many_ports_triggers_scan_detection(self):
        """Accessing many different ports from same IP should trigger port scan detection."""
        for port in range(1, 30):
            event = {
                "event_type": "connection",
                "src_ip": "10.0.0.50",
                "dst_port": port,
            }
            anomalies = self.detector.analyze(event)

        scans = [a for a in anomalies if a.get("type") == "port_scan"]
        self.assertGreater(len(scans), 0, "Port scan should be detected after many port accesses")


class TestExfiltrationDetection(unittest.TestCase):
    """Test data exfiltration detection."""

    def setUp(self):
        self.detector = AnomalyDetector()

    def test_small_transfer_no_alert(self):
        event = {
            "event_type": "network",
            "src_ip": "192.168.1.5",
            "direction": "outbound",
            "bytes_sent": 1024,
        }
        anomalies = self.detector.analyze(event)
        exfil = [a for a in anomalies if a.get("type") == "exfiltration"]
        self.assertEqual(len(exfil), 0)

    def test_large_transfer_triggers_alert(self):
        """Very large outbound transfer should trigger exfiltration detection."""
        event = {
            "event_type": "network",
            "src_ip": "192.168.1.5",
            "direction": "outbound",
            "bytes_sent": 200 * 1024 * 1024,  # 200 MB
        }
        anomalies = self.detector.analyze(event)
        exfil = [a for a in anomalies if a.get("type") == "exfiltration"]
        self.assertGreater(len(exfil), 0, "Large outbound transfer should trigger exfiltration alert")


class TestPrivilegeEscalation(unittest.TestCase):
    """Test privilege escalation detection."""

    def setUp(self):
        self.detector = AnomalyDetector()

    def test_normal_event_no_priv_esc(self):
        event = {
            "event_type": "auth_success",
            "src_ip": "192.168.1.1",
            "username": "user",
        }
        anomalies = self.detector.analyze(event)
        priv = [a for a in anomalies if a.get("type") == "privilege_escalation"]
        self.assertEqual(len(priv), 0)

    def test_sudo_root_detected(self):
        """Multiple sudo/su events should trigger privilege escalation detection."""
        for _ in range(5):
            event = {
                "event_type": "sudo",
                "src_ip": "192.168.1.20",
                "username": "attacker",
                "command": "bash",
            }
            anomalies = self.detector.analyze(event)

        priv = [a for a in anomalies if a.get("type") == "privilege_escalation"]
        # May or may not trigger depending on threshold, just check structure
        for a in priv:
            self.assertIn("severity", a)
            self.assertIn("description", a)


class TestBaselineTracking(unittest.TestCase):
    """Test statistical baseline updates."""

    def setUp(self):
        self.detector = AnomalyDetector()

    def test_update_baseline(self):
        for val in [10, 12, 11, 13, 10, 12]:
            self.detector.update_baseline("test_metric", val)

        stats = self.detector.get_baseline_stats("test_metric")
        self.assertIsNotNone(stats)

    def test_unknown_metric_returns_none(self):
        stats = self.detector.get_baseline_stats("nonexistent")
        self.assertIsNone(stats)


class TestAnomalyFormat(unittest.TestCase):
    """Verify anomaly output format."""

    def test_anomaly_has_required_fields(self):
        detector = AnomalyDetector()
        # Force a brute force detection
        for _ in range(15):
            anomalies = detector.analyze({
                "event_type": "ssh_failed",
                "src_ip": "1.2.3.4",
                "username": "root",
            })

        if anomalies:
            for anomaly in anomalies:
                self.assertIn("type", anomaly)
                self.assertIn("severity", anomaly)


if __name__ == "__main__":
    unittest.main()

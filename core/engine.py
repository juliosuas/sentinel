"""Main Sentinel Engine — Ingests logs, runs detection, triggers analysis."""

import logging
import threading
import time
from datetime import datetime, timezone
from queue import Queue, Empty
from typing import Optional

from core.config import Config
from core.detector import AnomalyDetector
from core.analyzer import AIAnalyzer
from core.responder import IncidentResponder
from core.correlator import EventCorrelator
from rules.rule_engine import RuleEngine

logger = logging.getLogger("sentinel.engine")


class SentinelEngine:
    """Central orchestrator for the Sentinel SOC platform."""

    def __init__(self, config: Optional[Config] = None, db=None):
        self.config = config or Config()
        self.db = db
        self.event_queue: Queue = Queue()
        self.alert_queue: Queue = Queue()
        self._running = False
        self._threads: list[threading.Thread] = []

        # Initialize subsystems
        self.detector = AnomalyDetector(self.config)
        self.rule_engine = RuleEngine(self.config.RULES_PATH)
        self.correlator = EventCorrelator()
        self.analyzer = AIAnalyzer(self.config)
        self.responder = IncidentResponder(self.config)

        # Callbacks for real-time event streaming
        self._event_callbacks: list = []
        self._alert_callbacks: list = []

        # Stats
        self.stats = {
            "events_processed": 0,
            "alerts_generated": 0,
            "incidents_created": 0,
            "start_time": None,
        }

    def on_event(self, callback):
        """Register a callback for new events."""
        self._event_callbacks.append(callback)

    def on_alert(self, callback):
        """Register a callback for new alerts."""
        self._alert_callbacks.append(callback)

    def ingest(self, event: dict):
        """Ingest a raw event into the processing pipeline."""
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        event.setdefault("source", "unknown")
        event.setdefault("severity", "info")
        self.event_queue.put(event)

    def start(self):
        """Start the engine processing loop."""
        if self._running:
            return
        self._running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()
        logger.info("Sentinel Engine starting...")

        # Event processing thread
        t = threading.Thread(target=self._process_events, daemon=True, name="event-processor")
        t.start()
        self._threads.append(t)

        # Alert processing thread
        t = threading.Thread(target=self._process_alerts, daemon=True, name="alert-processor")
        t.start()
        self._threads.append(t)

        logger.info("Sentinel Engine started.")

    def stop(self):
        """Stop the engine."""
        self._running = False
        for t in self._threads:
            t.join(timeout=5)
        self._threads.clear()
        logger.info("Sentinel Engine stopped.")

    def _process_events(self):
        """Main event processing loop."""
        while self._running:
            try:
                event = self.event_queue.get(timeout=1)
            except Empty:
                continue

            try:
                self._handle_event(event)
            except Exception:
                logger.exception("Error processing event: %s", event.get("raw", "")[:200])

    def _handle_event(self, event: dict):
        """Process a single event through the detection pipeline."""
        self.stats["events_processed"] += 1

        # Store event
        if self.db:
            self.db.store_event(event)

        # Notify listeners
        for cb in self._event_callbacks:
            try:
                cb(event)
            except Exception:
                logger.exception("Event callback error")

        # Run through correlation engine
        correlated = self.correlator.correlate(event)

        # Run rule engine
        rule_matches = self.rule_engine.evaluate(event)
        for match in rule_matches:
            alert = {
                "timestamp": event["timestamp"],
                "rule_id": match["id"],
                "rule_name": match["name"],
                "severity": match["severity"],
                "description": match["description"],
                "event": event,
                "correlated_events": correlated,
                "source": "rule_engine",
            }
            self.alert_queue.put(alert)

        # Run anomaly detection
        anomalies = self.detector.analyze(event)
        for anomaly in anomalies:
            alert = {
                "timestamp": event["timestamp"],
                "rule_id": f"anomaly_{anomaly['type']}",
                "rule_name": anomaly["name"],
                "severity": anomaly["severity"],
                "description": anomaly["description"],
                "event": event,
                "correlated_events": correlated,
                "source": "anomaly_detector",
            }
            self.alert_queue.put(alert)

    def _process_alerts(self):
        """Alert processing loop — AI analysis and response."""
        while self._running:
            try:
                alert = self.alert_queue.get(timeout=1)
            except Empty:
                continue

            try:
                self._handle_alert(alert)
            except Exception:
                logger.exception("Error processing alert: %s", alert.get("rule_name", ""))

    def _handle_alert(self, alert: dict):
        """Process an alert through AI analysis and response."""
        self.stats["alerts_generated"] += 1

        # AI analysis for high-severity alerts
        if alert["severity"] in ("high", "critical"):
            try:
                analysis = self.analyzer.analyze_alert(alert)
                alert["ai_analysis"] = analysis
            except Exception:
                logger.exception("AI analysis failed")
                alert["ai_analysis"] = None

        # Store alert
        if self.db:
            self.db.store_alert(alert)

        # Notify listeners
        for cb in self._alert_callbacks:
            try:
                cb(alert)
            except Exception:
                logger.exception("Alert callback error")

        # Auto-respond if configured
        if (
            self.config.AUTO_BLOCK_ENABLED
            and self._severity_gte(alert["severity"], self.config.AUTO_BLOCK_THRESHOLD)
        ):
            self._auto_respond(alert)

    def _auto_respond(self, alert: dict):
        """Trigger automated response for critical alerts."""
        event = alert.get("event", {})
        src_ip = event.get("src_ip")

        if src_ip:
            self.responder.block_ip(src_ip, reason=alert.get("rule_name", "auto-block"))

        # Send webhook alert
        self.responder.send_alert(alert)

        # Create incident
        incident = self.responder.create_incident(alert)
        if incident and self.db:
            self.db.store_incident(incident)
            self.stats["incidents_created"] += 1

    @staticmethod
    def _severity_gte(severity: str, threshold: str) -> bool:
        levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return levels.get(severity, 0) >= levels.get(threshold, 0)

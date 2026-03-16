"""Automated incident response — blocking, alerting, and ticketing."""

import json
import logging
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Optional

import requests

from core.config import Config

logger = logging.getLogger("sentinel.responder")


class IncidentResponder:
    """Automated incident response actions."""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self._blocked_ips: set[str] = set()
        self._response_log: list[dict] = []

    @property
    def response_log(self) -> list[dict]:
        return list(self._response_log)

    def block_ip(self, ip: str, reason: str = "", duration: int = 3600) -> dict:
        """Block an IP address using iptables."""
        action = {
            "id": str(uuid.uuid4())[:8],
            "type": "block_ip",
            "target": ip,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "pending",
        }

        if ip in self._blocked_ips:
            action["status"] = "skipped"
            action["message"] = f"IP {ip} already blocked"
            self._response_log.append(action)
            return action

        try:
            result = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                self._blocked_ips.add(ip)
                action["status"] = "success"
                action["message"] = f"Blocked IP {ip} via iptables"
                logger.info("Blocked IP %s (reason: %s)", ip, reason)
            else:
                action["status"] = "failed"
                action["message"] = f"iptables error: {result.stderr.strip()}"
                logger.error("Failed to block IP %s: %s", ip, result.stderr)
        except FileNotFoundError:
            action["status"] = "failed"
            action["message"] = "iptables not available"
            logger.warning("iptables not available — IP block simulated for %s", ip)
        except Exception as e:
            action["status"] = "failed"
            action["message"] = str(e)

        self._response_log.append(action)
        return action

    def unblock_ip(self, ip: str) -> dict:
        """Remove an IP block."""
        action = {
            "id": str(uuid.uuid4())[:8],
            "type": "unblock_ip",
            "target": ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "pending",
        }

        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=10,
            )
            self._blocked_ips.discard(ip)
            action["status"] = "success"
            action["message"] = f"Unblocked IP {ip}"
        except Exception as e:
            action["status"] = "failed"
            action["message"] = str(e)

        self._response_log.append(action)
        return action

    def kill_process(self, pid: int, reason: str = "") -> dict:
        """Kill a suspicious process."""
        action = {
            "id": str(uuid.uuid4())[:8],
            "type": "kill_process",
            "target": str(pid),
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "pending",
        }

        try:
            result = subprocess.run(
                ["kill", "-9", str(pid)],
                capture_output=True, text=True, timeout=10,
            )
            action["status"] = "success" if result.returncode == 0 else "failed"
            action["message"] = result.stderr.strip() or f"Killed PID {pid}"
        except Exception as e:
            action["status"] = "failed"
            action["message"] = str(e)

        self._response_log.append(action)
        return action

    def isolate_host(self, host: str, reason: str = "") -> dict:
        """Isolate a host by blocking all traffic except management."""
        action = {
            "id": str(uuid.uuid4())[:8],
            "type": "isolate_host",
            "target": host,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "pending",
        }

        try:
            # Block all traffic from/to host except SSH (for management)
            cmds = [
                ["iptables", "-A", "INPUT", "-s", host, "-p", "tcp", "--dport", "22", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-s", host, "-j", "DROP"],
                ["iptables", "-A", "OUTPUT", "-d", host, "-p", "tcp", "--sport", "22", "-j", "ACCEPT"],
                ["iptables", "-A", "OUTPUT", "-d", host, "-j", "DROP"],
            ]
            for cmd in cmds:
                subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            action["status"] = "success"
            action["message"] = f"Host {host} isolated (SSH management retained)"
            logger.info("Isolated host %s (reason: %s)", host, reason)
        except Exception as e:
            action["status"] = "failed"
            action["message"] = str(e)

        self._response_log.append(action)
        return action

    def send_alert(self, alert: dict) -> dict:
        """Send alert via webhook and/or WhatsApp."""
        action = {
            "id": str(uuid.uuid4())[:8],
            "type": "send_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "pending",
            "channels": [],
        }

        # Webhook (Slack/Discord/etc.)
        if self.config.WEBHOOK_URL:
            try:
                payload = {
                    "text": self._format_alert_text(alert),
                    "username": "Sentinel SOC",
                }
                resp = requests.post(
                    self.config.WEBHOOK_URL, json=payload, timeout=10
                )
                resp.raise_for_status()
                action["channels"].append("webhook")
            except Exception as e:
                logger.error("Webhook alert failed: %s", e)

        # WhatsApp
        if self.config.WHATSAPP_API_URL and self.config.WHATSAPP_API_TOKEN:
            try:
                resp = requests.post(
                    self.config.WHATSAPP_API_URL,
                    headers={"Authorization": f"Bearer {self.config.WHATSAPP_API_TOKEN}"},
                    json={"message": self._format_alert_text(alert)},
                    timeout=10,
                )
                resp.raise_for_status()
                action["channels"].append("whatsapp")
            except Exception as e:
                logger.error("WhatsApp alert failed: %s", e)

        action["status"] = "success" if action["channels"] else "no_channels"
        self._response_log.append(action)
        return action

    def create_incident(self, alert: dict) -> dict:
        """Generate an incident ticket from an alert."""
        incident = {
            "id": str(uuid.uuid4()),
            "title": f"[{alert.get('severity', 'unknown').upper()}] {alert.get('rule_name', 'Unknown Alert')}",
            "description": alert.get("description", ""),
            "severity": alert.get("severity", "medium"),
            "status": "open",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "alert": alert,
            "ai_analysis": alert.get("ai_analysis"),
            "response_actions": [],
        }

        action = {
            "id": str(uuid.uuid4())[:8],
            "type": "create_incident",
            "target": incident["id"],
            "timestamp": incident["created_at"],
            "status": "success",
            "message": f"Incident created: {incident['title']}",
        }
        self._response_log.append(action)
        logger.info("Incident created: %s", incident["title"])
        return incident

    def _format_alert_text(self, alert: dict) -> str:
        severity = alert.get("severity", "unknown").upper()
        emoji = {"INFO": "ℹ️", "LOW": "🟡", "MEDIUM": "🟠", "HIGH": "🔴", "CRITICAL": "🚨"}.get(severity, "⚠️")
        parts = [
            f"{emoji} *SENTINEL ALERT — {severity}*",
            f"*Rule:* {alert.get('rule_name', 'N/A')}",
            f"*Description:* {alert.get('description', 'N/A')}",
            f"*Time:* {alert.get('timestamp', 'N/A')}",
        ]
        event = alert.get("event", {})
        if event.get("src_ip"):
            parts.append(f"*Source IP:* {event['src_ip']}")
        ai = alert.get("ai_analysis")
        if ai:
            parts.append(f"\n*AI Analysis:*\n{ai.get('analysis', '')[:500]}")
        return "\n".join(parts)

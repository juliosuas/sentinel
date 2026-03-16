"""Sentinel configuration management."""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    # AI
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

    # Threat Intel
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
    DARKSEARCH_API_KEY = os.getenv("DARKSEARCH_API_KEY", "")

    # Alerts
    WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")
    WHATSAPP_API_URL = os.getenv("WHATSAPP_API_URL", "")
    WHATSAPP_API_TOKEN = os.getenv("WHATSAPP_API_TOKEN", "")

    # Syslog
    SYSLOG_HOST = os.getenv("SYSLOG_HOST", "0.0.0.0")
    SYSLOG_UDP_PORT = int(os.getenv("SYSLOG_UDP_PORT", "1514"))
    SYSLOG_TCP_PORT = int(os.getenv("SYSLOG_TCP_PORT", "1514"))

    # File Watcher
    WATCH_PATHS = os.getenv(
        "WATCH_PATHS", "/var/log/auth.log,/var/log/syslog"
    ).split(",")

    # Network
    NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "eth0")

    # Dashboard
    DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")
    DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8080"))
    SECRET_KEY = os.getenv("SECRET_KEY", "sentinel-dev-key")

    # Database
    DB_PATH = os.getenv("DB_PATH", str(BASE_DIR / "sentinel.db"))

    # Detection Thresholds
    BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
    BRUTE_FORCE_WINDOW = int(os.getenv("BRUTE_FORCE_WINDOW", "300"))
    PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", "20"))
    PORT_SCAN_WINDOW = int(os.getenv("PORT_SCAN_WINDOW", "60"))
    EXFIL_THRESHOLD_MB = int(os.getenv("EXFIL_THRESHOLD_MB", "100"))
    ANOMALY_ZSCORE_THRESHOLD = float(os.getenv("ANOMALY_ZSCORE_THRESHOLD", "3.0"))

    # Response
    AUTO_BLOCK_ENABLED = os.getenv("AUTO_BLOCK_ENABLED", "false").lower() == "true"
    AUTO_BLOCK_THRESHOLD = os.getenv("AUTO_BLOCK_THRESHOLD", "critical")

    # Rules
    RULES_PATH = str(BASE_DIR / "rules" / "default_rules.yaml")

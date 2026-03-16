"""Flask API server for the Sentinel dashboard and REST endpoints."""

import json
import logging
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from flask_socketio import SocketIO

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import Config
from core.engine import SentinelEngine
from backend.db import Database

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("sentinel.server")

config = Config()
app = Flask(__name__, static_folder=None)
app.config["SECRET_KEY"] = config.SECRET_KEY
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Initialize subsystems
db = Database(config)
engine = SentinelEngine(config, db)

# Wire up real-time streaming
def _emit_event(event):
    socketio.emit("event", event)

def _emit_alert(alert):
    # Serialize for JSON transport
    safe_alert = json.loads(json.dumps(alert, default=str))
    socketio.emit("alert", safe_alert)

engine.on_event(_emit_event)
engine.on_alert(_emit_alert)


# ── Dashboard ──

@app.route("/")
def dashboard():
    dashboard_path = Path(__file__).resolve().parent.parent / "ui" / "dashboard.html"
    return send_file(dashboard_path)


# ── Events API ──

@app.route("/api/events")
def get_events():
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    event_type = request.args.get("type")
    severity = request.args.get("severity")
    src_ip = request.args.get("src_ip")
    events = db.get_events(limit, offset, event_type, severity, src_ip)
    return jsonify({"events": events, "count": len(events)})


@app.route("/api/events", methods=["POST"])
def ingest_event():
    """Ingest an event via API."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body"}), 400
    engine.ingest(data)
    return jsonify({"status": "accepted"}), 202


# ── Alerts API ──

@app.route("/api/alerts")
def get_alerts():
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    severity = request.args.get("severity")
    alerts = db.get_alerts(limit, offset, severity)
    return jsonify({"alerts": alerts, "count": len(alerts)})


# ── Incidents API ──

@app.route("/api/incidents")
def get_incidents():
    limit = request.args.get("limit", 50, type=int)
    status = request.args.get("status")
    incidents = db.get_incidents(limit, status)
    return jsonify({"incidents": incidents, "count": len(incidents)})


@app.route("/api/incidents", methods=["POST"])
def create_incident():
    data = request.get_json()
    if not data or "title" not in data:
        return jsonify({"error": "title required"}), 400
    incident = {
        "id": data.get("id", str(hash(data["title"]))[:12]),
        "title": data["title"],
        "description": data.get("description", ""),
        "severity": data.get("severity", "medium"),
        "status": "open",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    db.store_incident(incident)
    return jsonify(incident), 201


@app.route("/api/incidents/<incident_id>", methods=["PATCH"])
def update_incident(incident_id):
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body"}), 400
    ok = db.update_incident(incident_id, data)
    if ok:
        return jsonify({"status": "updated"})
    return jsonify({"error": "Nothing to update"}), 400


# ── Stats API ──

@app.route("/api/stats")
def get_stats():
    stats = db.get_stats()
    stats["engine"] = engine.stats
    return jsonify(stats)


# ── Threat Intel API ──

@app.route("/api/threats")
def get_threats():
    return jsonify({
        "feed_stats": engine.detector.get_baseline_stats("threat_feed") or {},
        "blocked_ips": list(engine.responder._blocked_ips),
        "response_log": engine.responder.response_log[-50:],
    })


# ── Response API ──

@app.route("/api/respond", methods=["POST"])
def trigger_response():
    data = request.get_json()
    if not data or "action" not in data:
        return jsonify({"error": "action required"}), 400

    action = data["action"]
    target = data.get("target", "")
    reason = data.get("reason", "manual")

    if action == "block_ip":
        result = engine.responder.block_ip(target, reason)
    elif action == "unblock_ip":
        result = engine.responder.unblock_ip(target)
    elif action == "kill_process":
        result = engine.responder.kill_process(int(target), reason)
    elif action == "isolate_host":
        result = engine.responder.isolate_host(target, reason)
    elif action == "send_alert":
        result = engine.responder.send_alert(data.get("alert", {}))
    else:
        return jsonify({"error": f"Unknown action: {action}"}), 400

    return jsonify(result)


# ── Rules API ──

@app.route("/api/rules")
def get_rules():
    return jsonify({"rules": engine.rule_engine.get_rules()})


# ── WebSocket Events ──

@socketio.on("connect")
def handle_connect():
    logger.info("WebSocket client connected")
    socketio.emit("status", {
        "engine": engine.stats,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ── Demo Mode ──

def _run_demo():
    """Generate simulated events for demo/testing."""
    import time
    import random

    demo_ips = ["192.168.1.100", "10.0.0.50", "203.0.113.42", "198.51.100.7",
                "172.16.0.5", "45.33.32.156", "91.189.91.48"]
    demo_users = ["admin", "root", "deploy", "www-data", "jenkins"]

    while True:
        time.sleep(random.uniform(0.5, 3.0))
        event_type = random.choice([
            "ssh_failed", "ssh_failed", "ssh_failed",  # weighted toward failures
            "auth_success", "auth_failure",
            "connection", "network", "dns_query",
            "web_access", "sudo", "syslog",
        ])

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": random.choice(["syslog", "file:/var/log/auth.log", "network"]),
            "event_type": event_type,
            "src_ip": random.choice(demo_ips),
            "dst_ip": "10.0.0.1",
            "username": random.choice(demo_users),
            "hostname": "sentinel-host",
            "severity": random.choice(["info", "low", "medium"]),
        }

        if event_type == "ssh_failed":
            event["raw"] = f"Failed password for {event['username']} from {event['src_ip']} port {random.randint(1024, 65535)}"
            event["severity"] = "medium"
        elif event_type == "connection":
            event["dst_port"] = random.randint(1, 65535)
            event["tcp_flags"] = "S"
        elif event_type == "dns_query":
            event["dns_query"] = random.choice([
                "google.com", "github.com", "evil.duckdns.org",
                "update.microsoft.com", "suspicious.no-ip.com",
            ])
        elif event_type == "web_access":
            event["method"] = random.choice(["GET", "POST"])
            event["path"] = random.choice([
                "/index.html", "/api/data", "/login",
                "/../../etc/passwd", "/search?q=1 OR 1=1",
            ])
            event["status_code"] = random.choice([200, 200, 200, 404, 403, 500])
        elif event_type == "sudo":
            event["raw"] = f"{event['username']} : COMMAND=/bin/bash"

        engine.ingest(event)


# ── Main ──

if __name__ == "__main__":
    engine.start()
    logger.info("Sentinel Engine started")

    # Start demo mode if no real collectors configured
    if os.getenv("SENTINEL_DEMO", "true").lower() == "true":
        demo_thread = threading.Thread(target=_run_demo, daemon=True, name="demo")
        demo_thread.start()
        logger.info("Demo mode active — generating simulated events")

    logger.info("Dashboard: http://%s:%d", config.DASHBOARD_HOST, config.DASHBOARD_PORT)
    socketio.run(
        app,
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=False,
        allow_unsafe_werkzeug=True,
    )

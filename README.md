# SENTINEL

**AI-Powered Security Operations Center (SOC) Analyst**

Sentinel is a self-hosted security monitoring platform that uses AI to detect threats, analyze logs, and respond to incidents automatically. It combines statistical anomaly detection, YAML-based rule matching (Sigma-compatible), threat intelligence feeds, and LLM-powered analysis into a unified SOC platform.

## Features

- **Real-time Log Ingestion** — Syslog (UDP/TCP), file watching, network capture, API collectors
- **AI-Powered Analysis** — LLM interprets suspicious patterns and explains threats in plain language
- **Anomaly Detection** — Statistical (z-score, IQR), behavioral baselines, brute force, port scan, exfiltration, privilege escalation detection
- **Rule Engine** — YAML-based Sigma-compatible rules with 20+ built-in detections
- **Threat Intelligence** — AbuseIPDB, AlienVault OTX feeds, IOC checking, dark web monitoring
- **Automated Response** — IP blocking, process killing, host isolation, webhook/WhatsApp alerts, incident ticketing
- **Event Correlation** — Links related events across configurable time windows
- **Live Dashboard** — Dark-themed real-time UI with event stream, threat gauge, geographic attack map, alert timeline
- **REST API** — Full Flask API for integration with existing tooling

## Architecture

```
               +------------------+
               |   Collectors     |
               | syslog | file    |
               | network | api    |
               +--------+---------+
                        |
                        v
               +------------------+
               | SentinelEngine   |
               | (core/engine.py) |
               +--------+---------+
                        |
          +-------------+-------------+
          |             |             |
          v             v             v
   +-----------+  +-----------+  +-----------+
   | Detector  |  | Rules     |  | Correlator|
   | (anomaly) |  | (YAML)    |  | (linking) |
   +-----------+  +-----------+  +-----------+
          |             |             |
          +-------------+-------------+
                        |
                        v
               +------------------+
               |   AI Analyzer    |
               | (LLM analysis)   |
               +--------+---------+
                        |
               +--------+---------+
               |   Responder      |
               | block | alert    |
               | isolate | ticket |
               +--------+---------+
                        |
               +--------+---------+
               |  Backend / API   |
               |  Flask + SQLite  |
               +--------+---------+
                        |
               +--------+---------+
               |    Dashboard     |
               | (real-time UI)   |
               +------------------+
```

## Quick Start

```bash
# Clone and setup
git clone <repo-url> sentinel
cd sentinel

# Using Docker (recommended)
cp .env.example .env
# Edit .env with your API keys
docker-compose up -d

# Or run locally
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
make run
```

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
# AI Analysis
ANTHROPIC_API_KEY=your-key-here

# Threat Intel
ABUSEIPDB_API_KEY=your-key
OTX_API_KEY=your-key

# Alerts
WEBHOOK_URL=https://your-webhook-url
WHATSAPP_API_URL=https://api.whatsapp.com/...
WHATSAPP_API_TOKEN=your-token

# Dashboard
DASHBOARD_PORT=8080
```

## Usage

```bash
# Start the full platform
make run

# Run with specific collectors
make run-syslog
make run-filewatcher

# Run tests
make test

# Access dashboard
open http://localhost:8080
```

## Default Detection Rules

Sentinel ships with 20+ detection rules including:

| Rule | Description |
|------|-------------|
| SSH Brute Force | Multiple failed SSH logins from same IP |
| Login Spray | Failed logins across multiple accounts |
| Privilege Escalation | sudo/su abuse, unauthorized root access |
| Port Scan | Sequential port probing detection |
| Data Exfiltration | Large outbound data transfers |
| Web Shell | Detection of known web shell patterns |
| Crontab Modification | Unauthorized scheduled task changes |
| Suspicious DNS | DNS queries to known malicious domains |
| New User Creation | Unauthorized user account creation |
| Process Injection | Suspicious process execution chains |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/events` | List events (with filters) |
| GET | `/api/alerts` | List alerts |
| GET | `/api/incidents` | List incidents |
| POST | `/api/incidents` | Create incident |
| PATCH | `/api/incidents/<id>` | Update incident |
| GET | `/api/stats` | Dashboard statistics |
| GET | `/api/threats` | Threat intel data |
| POST | `/api/respond` | Trigger response action |

## License

MIT

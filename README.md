<p align="center">
  <h1 align="center">🔭 Sentinel</h1>
  <p align="center"><strong>AI-Powered Security Operations Center</strong></p>
  <p align="center">
    Your tireless SOC analyst — detecting threats, correlating events, responding automatically.
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Docker-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/Sigma-Compatible-orange" alt="Sigma Compatible">
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red" alt="MITRE ATT&CK">
  <img src="https://img.shields.io/badge/status-active-brightgreen" alt="Status">
</p>

---

## Why Sentinel?

Traditional SIEMs are expensive, complex, and require a team to operate. Sentinel combines **statistical anomaly detection**, **Sigma-compatible rule matching**, **threat intelligence feeds**, and **LLM-powered analysis** into a single self-hosted platform that works out of the box.

> **Think:** Splunk + CrowdStrike + an AI analyst — self-hosted, open-source, and free.

---

## ✨ Features

- 📥 **Real-time Log Ingestion** — Syslog (UDP/TCP), file watching, network capture, API collectors
- 🧠 **AI-Powered Analysis** — LLM interprets suspicious patterns and explains threats in plain language
- 📈 **Anomaly Detection** — Statistical (z-score, IQR), behavioral baselines, brute force, port scan, exfiltration, privilege escalation detection
- 📜 **Rule Engine** — YAML-based Sigma-compatible rules with 20+ built-in detections
- 🌐 **Threat Intelligence** — AbuseIPDB, AlienVault OTX feeds, IOC checking, dark web monitoring
- ⚡ **Automated Response** — IP blocking, process killing, host isolation, webhook/WhatsApp alerts, incident ticketing
- 🔗 **Event Correlation** — Links related events across configurable time windows
- 🎯 **Live Dashboard** — Dark-themed real-time UI with event stream, threat gauge, geographic attack map, alert timeline
- 🔌 **REST API** — Full Flask API for integration with existing tooling

---

## 🚀 Quick Start

```bash
git clone https://github.com/juliosuas/sentinel.git && cd sentinel
cp .env.example .env           # Add your API keys
docker-compose up -d           # → http://localhost:8080
```

> **Local install:** `pip install -r requirements.txt && make run`

---

## 📸 Screenshots

<p align="center">
  <em>Screenshots coming soon — live dashboard, attack map, alert timeline, incident response</em>
</p>

<!--
![Dashboard](docs/screenshots/dashboard.png)
![Attack Map](docs/screenshots/attack-map.png)
![Alert Timeline](docs/screenshots/alerts.png)
-->

---

## 🏗️ Architecture

```
               ┌──────────────────┐
               │    Collectors     │
               │ syslog │ file    │
               │ network │ api    │
               └────────┬─────────┘
                        │
                        ▼
               ┌──────────────────┐
               │  SentinelEngine  │
               │  (core/engine)   │
               └────────┬─────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
   ┌───────────┐ ┌───────────┐ ┌───────────┐
   │ Anomaly   │ │   Rules   │ │ Correlator│
   │ Detector  │ │  (Sigma)  │ │ (linking) │
   └─────┬─────┘ └─────┬─────┘ └─────┬─────┘
          └─────────────┼─────────────┘
                        ▼
               ┌──────────────────┐
               │   AI Analyzer    │
               │  (LLM analysis)  │
               └────────┬─────────┘
                        ▼
               ┌──────────────────┐
               │    Responder     │
               │ block │ alert    │
               │ isolate │ ticket │
               └────────┬─────────┘
                        ▼
               ┌──────────────────┐
               │  Flask API +     │
               │  Live Dashboard  │
               └──────────────────┘
```

## 🔍 Built-in Detection Rules

Sentinel ships with **20+ detection rules** including:

| Rule | Description | MITRE ATT&CK |
|------|-------------|---------------|
| SSH Brute Force | Multiple failed SSH logins from same IP | T1110 |
| Login Spray | Failed logins across multiple accounts | T1110.003 |
| Privilege Escalation | sudo/su abuse, unauthorized root access | T1548 |
| Port Scan | Sequential port probing detection | T1046 |
| Data Exfiltration | Large outbound data transfers | T1041 |
| Web Shell | Known web shell pattern detection | T1505.003 |
| Crontab Modification | Unauthorized scheduled task changes | T1053 |
| Suspicious DNS | DNS queries to known malicious domains | T1071.004 |
| New User Creation | Unauthorized user account creation | T1136 |
| Process Injection | Suspicious process execution chains | T1055 |

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/events` | List events (with filters) |
| `GET` | `/api/alerts` | List alerts |
| `GET` | `/api/incidents` | List incidents |
| `POST` | `/api/incidents` | Create incident |
| `PATCH` | `/api/incidents/<id>` | Update incident |
| `GET` | `/api/stats` | Dashboard statistics |
| `GET` | `/api/threats` | Threat intel data |
| `POST` | `/api/respond` | Trigger response action |

## ⚙️ Configuration

Copy `.env.example` to `.env` and configure:

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | AI-powered analysis |
| `ABUSEIPDB_API_KEY` | IP reputation lookups |
| `OTX_API_KEY` | AlienVault OTX threat intel |
| `WEBHOOK_URL` | Alert webhook URL |
| `WHATSAPP_API_*` | WhatsApp alerting |
| `DASHBOARD_PORT` | Dashboard port (default: 8080) |

## 🏁 Compared to Alternatives

| Feature | Sentinel | Splunk | Wazuh | OSSEC |
|---------|----------|--------|-------|-------|
| AI-powered analysis | ✅ LLM | ❌ | ❌ | ❌ |
| Self-hosted | ✅ | ✅ | ✅ | ✅ |
| Cost | ✅ Free/OSS | ❌ $$$$$ | ✅ Free | ✅ Free |
| Sigma rules | ✅ | ✅ Plugin | ❌ | ❌ |
| Auto-response | ✅ | ✅ SOAR $$ | ⚠️ Basic | ⚠️ Basic |
| Setup time | ~5 min | Days | Hours | Hours |
| Threat intel feeds | ✅ Built-in | ✅ Add-on | ✅ | ❌ |

## 🛠️ Development

```bash
make install        # Install dependencies
make test           # Run test suite
make run            # Start full platform
make run-syslog     # Start with syslog collector
make run-filewatcher # Start with file watcher
```

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-detection`)
3. Commit your changes (`git commit -m 'Add new detection rule'`)
4. Push to the branch (`git push origin feature/new-detection`)
5. Open a Pull Request

Check the issues tab for areas where help is needed — especially new detection rules and collector plugins.

## ⚖️ Legal Disclaimer

Sentinel is designed for **authorized security monitoring** of systems you own or have explicit permission to monitor. Unauthorized interception or monitoring of network traffic may violate local, state, and federal laws. The authors assume no liability for misuse. Ensure compliance with all applicable laws and organizational policies before deployment.

## 📄 License

MIT

---

<p align="center">
  <strong>Sentinel</strong> — Because threats don't sleep, and neither should your SOC. 🌙
</p>

---
### 🌱 Also check out
**[AI Garden](https://github.com/juliosuas/ai-garden)** — A living world built exclusively by AI agents. Watch it grow.

# AI Analysis Verification Framework

> How Sentinel ensures AI-generated security analysis is accurate, actionable, and trustworthy.

---

## Overview

Sentinel's AI Analyzer is not a black box. Every AI-generated insight passes through a multi-stage verification pipeline that scores confidence, reduces false positives, and correlates evidence across data sources before any automated response fires.

This document describes the full verification methodology — useful for auditors, contributors, and operators who need to trust (and tune) the system.

---

## 1. Confidence Scoring Model

Every AI analysis output includes a **confidence score** (0–100) derived from three independent signals:

### Signal Weights

| Signal | Weight | Source |
|--------|--------|--------|
| **Evidence Strength** | 40% | Number and quality of corroborating log entries, IOCs, and rule matches |
| **Pattern Consistency** | 35% | How well the observed behavior matches known attack patterns (MITRE ATT&CK) |
| **Historical Context** | 25% | Baseline deviation — how anomalous this is relative to the environment's normal behavior |

### Confidence Tiers

| Tier | Score | Automated Action | Human Expectation |
|------|-------|------------------|-------------------|
| **Critical** | 90–100 | Auto-respond: block IP, isolate host, kill process | Post-incident review within 1h |
| **High** | 75–89 | Auto-respond with safeguards (reversible actions only) | Review within 4h |
| **Medium** | 50–74 | Alert generated, enriched with AI context | Analyst triage required |
| **Low** | 25–49 | Event enriched, logged with context | Batch review (daily/weekly) |
| **Informational** | 0–24 | Metadata enrichment only | No action required |

### Score Calculation

```
confidence = (evidence_score × 0.40) + (pattern_score × 0.35) + (context_score × 0.25)
```

**Evidence score** counts:
- Direct IOC match (known-bad IP, hash, domain): +30
- Sigma rule hit: +25
- Threat intel feed match (AbuseIPDB, OTX): +20
- Anomaly detector trigger: +15
- Single log entry with suspicious keywords: +5
- Capped at 100

**Pattern score** evaluates:
- Full MITRE ATT&CK technique match with ≥3 indicators: 100
- Partial technique match (2 indicators): 70
- Single indicator matching a technique: 40
- No technique match but anomalous: 15

**Context score** uses:
- Z-score > 4σ from baseline: 100
- Z-score 3–4σ: 75
- Z-score 2–3σ: 50
- Z-score 1–2σ: 25
- Within 1σ: 5

---

## 2. False Positive Reduction Pipeline

False positives are the #1 reason SOC teams burn out. Sentinel addresses this at multiple stages:

### Stage 1: Pre-Analysis Filtering

Before events reach the AI Analyzer:
- **Allowlist matching** — Known-good IPs, domains, and process hashes are filtered out
- **Deduplication** — Identical events within a 60-second window are collapsed
- **Baseline exclusion** — Events matching established behavioral baselines (e.g., daily backup traffic spikes) are tagged as `baseline_expected`

### Stage 2: Multi-Source Corroboration

The AI Analyzer requires **at least two independent signals** before elevating an event above `Low` confidence:

| Single Signal | Result |
|--------------|--------|
| Only anomaly detector triggered | Low confidence — log and enrich |
| Only Sigma rule matched | Low–Medium — depends on rule severity |
| Only threat intel matched | Low–Medium — depends on source reputation |

| Corroborated Signals | Result |
|---------------------|--------|
| Anomaly + Sigma rule | Medium–High |
| Anomaly + Threat intel | Medium–High |
| Sigma rule + Threat intel | High |
| All three signals | High–Critical |

### Stage 3: AI Cross-Validation

The LLM receives the raw evidence and is prompted to:

1. **Identify the most likely benign explanation** for the observed activity
2. **Rate the benign explanation's plausibility** (0–100)
3. **Compare** the malicious vs. benign interpretation
4. Only proceed with the malicious interpretation if `malicious_score > benign_score + 20`

This adversarial self-check reduces false positives from common operational patterns (deployments, backups, legitimate scans).

### Stage 4: Feedback Loop

- Analysts can mark alerts as `true_positive`, `false_positive`, or `needs_tuning`
- False positive feedback is aggregated weekly to:
  - Auto-add entries to allowlists
  - Adjust anomaly detection baselines
  - Fine-tune Sigma rule thresholds
  - Update AI Analyzer prompt context

### False Positive Rate Targets

| Detection Type | Target FP Rate | Measurement |
|---------------|---------------|-------------|
| Brute Force | < 2% | Validated against auth logs |
| Port Scan | < 5% | Confirmed vs. legitimate scanning tools |
| Data Exfiltration | < 10% | Volume thresholds tuned to baseline |
| Privilege Escalation | < 3% | Process chain verification |
| Web Shell | < 1% | Hash + behavioral dual check |

---

## 3. Correlation Validation

Sentinel's Correlator links related events into **incident chains**. The AI Analyzer validates these chains to ensure they represent coherent attack narratives, not coincidental groupings.

### Correlation Rules

Events are correlated when they share:
- **Same source IP** within a configurable time window (default: 30 minutes)
- **Same target host** with escalating severity
- **Same user account** across multiple systems
- **Sequential MITRE ATT&CK phases** (e.g., Reconnaissance → Initial Access → Execution)

### Chain Validation

The AI Analyzer reviews each correlated chain and:

1. **Assesses narrative coherence** — Do these events tell a logical attack story?
2. **Identifies gaps** — Are there missing steps that suggest coincidence rather than attack?
3. **Calculates chain confidence** — Geometric mean of individual event confidences, weighted by chain length:

```
chain_confidence = (Π event_confidences)^(1/n) × length_bonus

length_bonus:
  2 events: 1.0
  3 events: 1.1
  4 events: 1.2
  5+ events: 1.3 (capped)
```

4. **Maps to kill chain phase** — Assigns the chain to the furthest-progressed phase:

| Kill Chain Phase | Urgency | Auto-Response |
|-----------------|---------|---------------|
| Reconnaissance | Low | Monitor |
| Initial Access | Medium | Alert |
| Execution | High | Alert + Contain |
| Persistence | High | Alert + Contain |
| Lateral Movement | Critical | Isolate |
| Exfiltration | Critical | Block + Isolate |

### Temporal Decay

Correlation confidence decays over time. Events separated by more than the correlation window receive a penalty:

```
decay_factor = e^(-time_gap / window_size)
```

This prevents stale events from inflating chain confidence.

---

## 4. Verification Patterns by Detection Type

### Brute Force Verification

```
Trigger: ≥5 failed auth attempts from same source within 5 minutes
Verify:
  1. Confirm source IP is not in allowlist (VPN, jump box)
  2. Check if target accounts exist (non-existent = spray, existing = targeted)
  3. Verify no successful auth follows (success after failures = compromised)
  4. Cross-reference source with threat intel feeds
  5. Check geographic anomaly (is source from unusual country?)
Confidence boost: +20 if followed by successful auth (credential compromise)
```

### Port Scan Verification

```
Trigger: ≥10 unique destination ports from same source within 60 seconds
Verify:
  1. Exclude known scanning tools (Nessus, Qualys) by source IP
  2. Check scan pattern (sequential = nmap default, random = more sophisticated)
  3. Verify target responses (open ports found = higher risk)
  4. Cross-reference timing with scheduled security scans
  5. Check for follow-up exploitation attempts on discovered ports
Confidence boost: +25 if exploitation attempt follows within 10 minutes
```

### Data Exfiltration Verification

```
Trigger: Outbound transfer volume exceeds 3σ from source baseline
Verify:
  1. Check destination against known cloud storage, CDN, backup services
  2. Verify transfer timing (business hours = likely legitimate)
  3. Analyze protocol (DNS tunneling, ICMP = suspicious; HTTPS to known SaaS = likely OK)
  4. Check for preceding unauthorized access events
  5. Verify file types if DLP integration is active
Confidence boost: +30 if preceded by privilege escalation in same session
```

### Privilege Escalation Verification

```
Trigger: Process ancestry shows unprivileged → root/SYSTEM transition
Verify:
  1. Check if escalation method is expected (sudo with valid policy)
  2. Verify user is authorized for privilege escalation
  3. Analyze command executed post-escalation
  4. Cross-reference with change management tickets (if integrated)
  5. Check for follow-up persistence mechanisms
Confidence boost: +25 if unexpected binary used for escalation (GTFOBins match)
```

---

## 5. Tuning and Calibration

### Baseline Calibration Period

New Sentinel deployments enter a **14-day learning period** where:
- Anomaly detection thresholds are being established
- AI confidence scores are conservative (capped at Medium)
- No automated responses fire (alert-only mode)
- Operators are encouraged to mark false positives to train the system

### Threshold Adjustment

Operators can tune per-rule thresholds in `config/detection_thresholds.yaml`:

```yaml
brute_force:
  min_attempts: 5          # Lower = more sensitive, more FP
  time_window_seconds: 300
  confidence_floor: 50     # Minimum confidence to alert

port_scan:
  min_ports: 10
  time_window_seconds: 60
  exclude_sources:
    - 10.0.0.0/8           # Internal scanner subnet
  confidence_floor: 40

exfiltration:
  sigma_threshold: 3.0     # Standard deviations from baseline
  min_bytes: 104857600     # 100MB minimum to trigger
  confidence_floor: 45
```

### AI Analyzer Prompt Tuning

The AI Analyzer's system prompt can be customized in `config/ai_analyzer_prompt.md` to:
- Add organization-specific context (e.g., "We run daily 2AM backups to AWS S3")
- Adjust verbosity of analysis output
- Include domain-specific false positive patterns
- Define custom severity mappings

---

## 6. Audit Trail

Every AI analysis decision is logged with full provenance:

```json
{
  "analysis_id": "sa-20240315-001",
  "event_ids": ["evt-1234", "evt-1235", "evt-1236"],
  "confidence": 87,
  "tier": "high",
  "evidence": {
    "sigma_rules": ["ssh_brute_force"],
    "threat_intel": ["abuseipdb:192.168.1.100:95"],
    "anomaly_scores": [{"metric": "failed_auth_rate", "zscore": 4.2}]
  },
  "ai_analysis": "Multiple failed SSH authentication attempts from 192.168.1.100...",
  "benign_assessment": "Possible misconfigured service account",
  "benign_plausibility": 15,
  "action_taken": "ip_block",
  "action_reversible": true,
  "timestamp": "2024-03-15T14:32:00Z",
  "model": "claude-3-opus",
  "prompt_version": "v2.1"
}
```

This ensures every automated decision can be audited, explained, and reversed if needed.

---

## Summary

Sentinel's verification framework ensures that AI analysis is:

- **Transparent** — Every score has a clear derivation
- **Conservative** — Multiple signals required before action
- **Self-correcting** — Feedback loops reduce false positives over time
- **Auditable** — Full provenance chain for every decision
- **Tunable** — Operators control thresholds, allowlists, and AI prompts

The goal: AI as a force multiplier for human analysts, not a replacement. High-confidence automation handles the obvious; everything else surfaces for human judgment.

# Sentinel AI Analysis Verification

## Confidence Scoring Model

Sentinel assigns a confidence score (0.0–1.0) to every AI-generated alert:

| Score Range | Classification | Action |
|-------------|---------------|--------|
| 0.9–1.0 | Critical Confidence | Auto-respond, immediate SOC notification |
| 0.7–0.89 | High Confidence | SOC review within 15 minutes |
| 0.5–0.69 | Medium Confidence | Queue for analyst review |
| 0.3–0.49 | Low Confidence | Enrich with additional data sources |
| 0.0–0.29 | Noise | Log only, suppress alert |

## False Positive Reduction

1. **Statistical Baseline:** Z-score and IQR analysis against 30-day behavioral baseline
2. **Multi-Source Correlation:** Alerts confirmed by 2+ detection engines score higher
3. **Threat Intel Enrichment:** IOC matches against AbuseIPDB/AlienVault OTX boost confidence
4. **Contextual Analysis:** LLM evaluates alert context against known benign patterns
5. **Feedback Loop:** Analyst verdicts retrain scoring weights weekly

## Alert Correlation Validation

Sentinel correlates related events within configurable time windows:
- Same source IP across multiple rule triggers → campaign detection
- Sequential MITRE ATT&CK stages → kill chain reconstruction
- Cross-log correlation (firewall + auth + endpoint) → comprehensive incident view

## Verification Procedures

1. **Monthly False Positive Audit:** Sample 100 alerts, measure FP rate (target: <5%)
2. **Detection Coverage Test:** Run MITRE ATT&CK atomic tests, verify detection rate
3. **Response Time Measurement:** Track alert-to-action latency
4. **AI Explanation Review:** Verify LLM-generated explanations are accurate and actionable

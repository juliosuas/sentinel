"""AI-powered log analyzer using LLMs to interpret suspicious patterns."""

import json
import logging
from typing import Optional

from core.config import Config

logger = logging.getLogger("sentinel.analyzer")


class AIAnalyzer:
    """Uses Claude to analyze security events and explain threats in plain language."""

    SYSTEM_PROMPT = """You are Sentinel, an expert SOC (Security Operations Center) analyst AI.
Your job is to analyze security alerts and events, then provide:
1. A clear explanation of what happened
2. The likely attack technique (MITRE ATT&CK mapping if applicable)
3. Severity assessment with confidence level
4. Recommended response actions
5. Whether this is likely a true positive or false positive

Be concise but thorough. Use technical security terminology appropriately."""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.config.ANTHROPIC_API_KEY)
            except Exception:
                logger.warning("Anthropic client not available — AI analysis disabled")
        return self._client

    def analyze_alert(self, alert: dict) -> Optional[dict]:
        """Analyze an alert using AI and return structured analysis."""
        if not self.client:
            return None

        prompt = self._build_prompt(alert)

        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=1024,
                system=self.SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.content[0].text
            return self._parse_response(text, alert)
        except Exception:
            logger.exception("AI analysis request failed")
            return None

    def analyze_batch(self, events: list[dict]) -> Optional[dict]:
        """Analyze a batch of correlated events."""
        if not self.client or not events:
            return None

        summary = json.dumps(events[:20], indent=2, default=str)
        prompt = f"""Analyze the following batch of {len(events)} correlated security events.
Identify patterns, determine if this represents a coordinated attack, and provide your assessment.

Events:
{summary}"""

        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=1500,
                system=self.SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            return {
                "analysis": response.content[0].text,
                "event_count": len(events),
                "type": "batch_analysis",
            }
        except Exception:
            logger.exception("Batch AI analysis failed")
            return None

    def _build_prompt(self, alert: dict) -> str:
        event = alert.get("event", {})
        correlated = alert.get("correlated_events", [])

        parts = [
            f"**Alert:** {alert.get('rule_name', 'Unknown')}",
            f"**Severity:** {alert.get('severity', 'unknown')}",
            f"**Description:** {alert.get('description', 'N/A')}",
            f"**Timestamp:** {alert.get('timestamp', 'N/A')}",
            f"**Source:** {alert.get('source', 'N/A')}",
            "",
            "**Event Data:**",
            json.dumps(event, indent=2, default=str),
        ]

        if correlated:
            parts.append(f"\n**Correlated Events ({len(correlated)}):**")
            parts.append(json.dumps(correlated[:10], indent=2, default=str))

        parts.append("\nProvide your security analysis of this alert.")
        return "\n".join(parts)

    def _parse_response(self, text: str, alert: dict) -> dict:
        return {
            "analysis": text,
            "alert_rule": alert.get("rule_name"),
            "severity": alert.get("severity"),
            "type": "ai_analysis",
        }

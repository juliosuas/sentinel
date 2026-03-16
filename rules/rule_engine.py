"""YAML-based detection rule engine (Sigma-compatible format)."""

import logging
import re
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger("sentinel.rules")


class Rule:
    """A single detection rule."""

    def __init__(self, data: dict):
        self.id = data.get("id", "unknown")
        self.name = data.get("name", "Unnamed Rule")
        self.description = data.get("description", "")
        self.severity = data.get("severity", "medium")
        self.enabled = data.get("enabled", True)
        self.tags = data.get("tags", [])

        # Detection logic
        detection = data.get("detection", {})
        self._conditions = detection.get("condition", [])
        self._selections = {
            k: v for k, v in detection.items() if k != "condition"
        }

        # Compiled regex patterns
        self._compiled: dict[str, list] = {}
        self._compile_selections()

    def _compile_selections(self):
        """Pre-compile regex patterns in selections."""
        for name, selection in self._selections.items():
            compiled = []
            if isinstance(selection, dict):
                for field, patterns in selection.items():
                    if isinstance(patterns, str):
                        patterns = [patterns]
                    if isinstance(patterns, list):
                        for p in patterns:
                            # Support wildcards like Sigma rules
                            regex = self._pattern_to_regex(str(p))
                            compiled.append((field, re.compile(regex, re.IGNORECASE)))
            self._compiled[name] = compiled

    @staticmethod
    def _pattern_to_regex(pattern: str) -> str:
        """Convert a Sigma-style pattern to regex."""
        # Escape regex special chars, then convert wildcards
        escaped = re.escape(pattern)
        escaped = escaped.replace(r"\*", ".*")
        escaped = escaped.replace(r"\?", ".")
        return f"^{escaped}$"

    def evaluate(self, event: dict) -> bool:
        """Evaluate this rule against an event."""
        if not self.enabled:
            return False

        # Evaluate each selection
        selection_results = {}
        for name, compiled_patterns in self._compiled.items():
            selection_results[name] = self._eval_selection(compiled_patterns, event)

        # Evaluate condition
        if not self._conditions:
            # Default: all selections must match
            return all(selection_results.values()) if selection_results else False

        condition = self._conditions if isinstance(self._conditions, str) else str(self._conditions)

        # Parse simple condition expressions
        return self._eval_condition(condition, selection_results)

    def _eval_selection(self, compiled_patterns: list, event: dict) -> bool:
        """Evaluate a single selection against an event."""
        if not compiled_patterns:
            return False

        for field, pattern in compiled_patterns:
            value = self._get_field(event, field)
            if value is None:
                return False
            if not pattern.search(str(value)):
                return False
        return True

    @staticmethod
    def _get_field(event: dict, field: str) -> Optional[str]:
        """Get a field from an event, supporting dot notation."""
        parts = field.split(".")
        current = event
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
            if current is None:
                return None
        return str(current)

    @staticmethod
    def _eval_condition(condition: str, results: dict) -> bool:
        """Evaluate a simple condition expression."""
        # Handle: "selection1 and selection2", "selection1 or selection2",
        # "selection1 and not selection2", "all of selection*"
        condition = condition.strip()

        if condition.startswith("all of "):
            prefix = condition[7:].replace("*", "")
            return all(v for k, v in results.items() if k.startswith(prefix))

        if condition.startswith("any of "):
            prefix = condition[7:].replace("*", "")
            return any(v for k, v in results.items() if k.startswith(prefix))

        # Simple boolean expression
        # Replace selection names with their boolean values
        expr = condition
        for name, result in sorted(results.items(), key=lambda x: -len(x[0])):
            expr = expr.replace(name, str(result))

        expr = expr.replace(" and ", " and ").replace(" or ", " or ").replace("not ", "not ")
        try:
            return bool(eval(expr, {"__builtins__": {}}, {"True": True, "False": False, "not": lambda x: not x}))
        except Exception:
            return False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "enabled": self.enabled,
            "tags": self.tags,
        }


class RuleEngine:
    """Loads and evaluates YAML detection rules."""

    def __init__(self, rules_path: Optional[str] = None):
        self.rules: list[Rule] = []
        if rules_path:
            self.load_rules(rules_path)

    def load_rules(self, path: str):
        """Load rules from a YAML file."""
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f)

            if not data or "rules" not in data:
                logger.warning("No rules found in %s", path)
                return

            for rule_data in data["rules"]:
                try:
                    rule = Rule(rule_data)
                    self.rules.append(rule)
                except Exception:
                    logger.exception("Failed to load rule: %s", rule_data.get("id", "?"))

            logger.info("Loaded %d rules from %s", len(self.rules), path)
        except FileNotFoundError:
            logger.warning("Rules file not found: %s", path)
        except Exception:
            logger.exception("Failed to load rules from %s", path)

    def add_rule(self, rule_data: dict):
        """Add a rule from a dict."""
        rule = Rule(rule_data)
        self.rules.append(rule)

    def evaluate(self, event: dict) -> list[dict]:
        """Evaluate all rules against an event. Returns list of matched rules."""
        matches = []
        for rule in self.rules:
            try:
                if rule.evaluate(event):
                    matches.append(rule.to_dict())
            except Exception:
                logger.exception("Rule evaluation failed: %s", rule.id)
        return matches

    def get_rules(self) -> list[dict]:
        """Get all loaded rules."""
        return [r.to_dict() for r in self.rules]

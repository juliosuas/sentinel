"""Tests for SENTINEL rule engine."""

import os
import unittest

from rules.rule_engine import Rule, RuleEngine


RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules", "default_rules.yaml")


class TestRuleInit(unittest.TestCase):
    """Test Rule object creation."""

    def test_create_rule_from_dict(self):
        rule = Rule({
            "id": "test_001",
            "name": "Test Rule",
            "description": "A test rule",
            "severity": "high",
            "detection": {
                "selection": {"event_type": "ssh_failed"},
                "condition": "selection",
            },
        })
        self.assertEqual(rule.id, "test_001")
        self.assertEqual(rule.name, "Test Rule")
        self.assertEqual(rule.severity, "high")

    def test_rule_enabled_by_default(self):
        rule = Rule({
            "id": "test_002",
            "name": "Enabled Rule",
            "detection": {
                "selection": {"event_type": "test"},
                "condition": "selection",
            },
        })
        self.assertTrue(rule.enabled)

    def test_rule_to_dict(self):
        data = {
            "id": "test_003",
            "name": "Serializable Rule",
            "description": "desc",
            "severity": "low",
            "tags": ["test"],
            "detection": {
                "selection": {"event_type": "test"},
                "condition": "selection",
            },
        }
        rule = Rule(data)
        d = rule.to_dict()
        self.assertEqual(d["id"], "test_003")
        self.assertEqual(d["name"], "Serializable Rule")
        self.assertIn("severity", d)


class TestRuleEvaluation(unittest.TestCase):
    """Test individual rule evaluation."""

    def test_simple_match(self):
        rule = Rule({
            "id": "match_001",
            "name": "SSH Failed Match",
            "detection": {
                "selection": {"event_type": "ssh_failed"},
                "condition": "selection",
            },
        })
        event = {"event_type": "ssh_failed", "src_ip": "10.0.0.1"}
        self.assertTrue(rule.evaluate(event))

    def test_no_match(self):
        rule = Rule({
            "id": "match_002",
            "name": "SSH Failed Match",
            "detection": {
                "selection": {"event_type": "ssh_failed"},
                "condition": "selection",
            },
        })
        event = {"event_type": "auth_success", "src_ip": "10.0.0.1"}
        self.assertFalse(rule.evaluate(event))

    def test_wildcard_match(self):
        rule = Rule({
            "id": "wild_001",
            "name": "Wildcard Test",
            "detection": {
                "selection": {"event_type": "ssh_*"},
                "condition": "selection",
            },
        })
        self.assertTrue(rule.evaluate({"event_type": "ssh_failed"}))
        self.assertTrue(rule.evaluate({"event_type": "ssh_success"}))
        self.assertFalse(rule.evaluate({"event_type": "auth_success"}))

    def test_multiple_values_in_selection(self):
        rule = Rule({
            "id": "multi_001",
            "name": "Multi Value",
            "detection": {
                "selection": {"event_type": ["ssh_failed", "auth_failure"]},
                "condition": "selection",
            },
        })
        self.assertTrue(rule.evaluate({"event_type": "ssh_failed"}))
        self.assertTrue(rule.evaluate({"event_type": "auth_failure"}))
        self.assertFalse(rule.evaluate({"event_type": "auth_success"}))

    def test_disabled_rule_no_match(self):
        rule = Rule({
            "id": "disabled_001",
            "name": "Disabled",
            "enabled": False,
            "detection": {
                "selection": {"event_type": "ssh_failed"},
                "condition": "selection",
            },
        })
        event = {"event_type": "ssh_failed"}
        self.assertFalse(rule.evaluate(event))

    def test_multi_field_selection(self):
        """Rule with multiple fields in selection — all must match."""
        rule = Rule({
            "id": "multi_field_001",
            "name": "Multi Field",
            "detection": {
                "selection": {
                    "event_type": "ssh_failed",
                    "username": "root",
                },
                "condition": "selection",
            },
        })
        self.assertTrue(rule.evaluate({"event_type": "ssh_failed", "username": "root"}))
        self.assertFalse(rule.evaluate({"event_type": "ssh_failed", "username": "admin"}))


class TestRuleEngine(unittest.TestCase):
    """Test the rule engine."""

    def test_engine_init(self):
        engine = RuleEngine()
        self.assertIsNotNone(engine)

    def test_add_rule(self):
        engine = RuleEngine()
        engine.add_rule({
            "id": "added_001",
            "name": "Added Rule",
            "severity": "medium",
            "detection": {
                "selection": {"event_type": "test"},
                "condition": "selection",
            },
        })
        rules = engine.get_rules()
        self.assertGreaterEqual(len(rules), 1)
        ids = [r["id"] for r in rules]
        self.assertIn("added_001", ids)

    def test_evaluate_returns_matches(self):
        engine = RuleEngine()
        engine.add_rule({
            "id": "eval_001",
            "name": "Eval Rule",
            "severity": "high",
            "detection": {
                "selection": {"event_type": "ssh_failed"},
                "condition": "selection",
            },
        })
        matches = engine.evaluate({"event_type": "ssh_failed", "src_ip": "1.2.3.4"})
        self.assertIsInstance(matches, list)
        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0]["rule_id"], "eval_001")

    def test_evaluate_no_match(self):
        engine = RuleEngine()
        engine.add_rule({
            "id": "eval_002",
            "name": "No Match Rule",
            "severity": "low",
            "detection": {
                "selection": {"event_type": "ssh_failed"},
                "condition": "selection",
            },
        })
        matches = engine.evaluate({"event_type": "auth_success"})
        self.assertEqual(len(matches), 0)

    def test_get_rules_format(self):
        engine = RuleEngine()
        engine.add_rule({
            "id": "fmt_001",
            "name": "Format Rule",
            "severity": "medium",
            "tags": ["T1110"],
            "detection": {
                "selection": {"event_type": "test"},
                "condition": "selection",
            },
        })
        rules = engine.get_rules()
        self.assertIsInstance(rules, list)
        rule = next(r for r in rules if r["id"] == "fmt_001")
        self.assertIn("name", rule)
        self.assertIn("severity", rule)


class TestDefaultRulesLoading(unittest.TestCase):
    """Test loading and evaluating default rules."""

    def setUp(self):
        self.engine = RuleEngine()
        if os.path.exists(RULES_PATH):
            self.engine.load_rules(RULES_PATH)
            self.rules_available = True
        else:
            self.rules_available = False

    def test_default_rules_loaded(self):
        if not self.rules_available:
            self.skipTest("default_rules.yaml not found")
        rules = self.engine.get_rules()
        self.assertGreater(len(rules), 0, "Should load at least one rule from YAML")

    def test_ssh_brute_force_rule_exists(self):
        if not self.rules_available:
            self.skipTest("default_rules.yaml not found")
        rules = self.engine.get_rules()
        ids = [r["id"] for r in rules]
        self.assertIn("ssh_brute_force", ids)

    def test_ssh_brute_force_matches(self):
        if not self.rules_available:
            self.skipTest("default_rules.yaml not found")
        event = {"event_type": "ssh_failed", "src_ip": "10.0.0.1", "username": "root"}
        matches = self.engine.evaluate(event)
        rule_ids = [m["rule_id"] for m in matches]
        self.assertIn("ssh_brute_force", rule_ids)

    def test_sql_injection_rule_matches(self):
        if not self.rules_available:
            self.skipTest("default_rules.yaml not found")
        event = {
            "event_type": "web_access",
            "path": "/search?q=' OR 1=1 --",
            "method": "GET",
        }
        matches = self.engine.evaluate(event)
        rule_ids = [m["rule_id"] for m in matches]
        self.assertIn("sql_injection", rule_ids)

    def test_benign_event_no_rules_fire(self):
        if not self.rules_available:
            self.skipTest("default_rules.yaml not found")
        event = {
            "event_type": "auth_success",
            "src_ip": "192.168.1.1",
            "username": "admin",
        }
        matches = self.engine.evaluate(event)
        # auth_success may match some rules, but should not match attack rules
        attack_rules = [m for m in matches if m.get("severity") in ("critical", "high")]
        self.assertEqual(len(attack_rules), 0, "Benign event should not trigger high/critical rules")


if __name__ == "__main__":
    unittest.main()

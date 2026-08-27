import json
import tempfile
import unittest
from pathlib import Path

from honey_agent_lab.models import Message
from honey_agent_lab.risk import RiskScorer
from honey_agent_lab.rule_loader import load_rule_schema, load_rules


class RuleLoaderTests(unittest.TestCase):
    def test_default_rules_and_schema_load(self):
        self.assertEqual(len(load_rules()), 8)
        self.assertEqual(len(RiskScorer.RULES), 8)
        schema = load_rule_schema()
        self.assertEqual(schema["type"], "array")
        self.assertIn("$defs", schema)

    def test_custom_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_text(json.dumps([{
                "code": "TEST_SIGNAL",
                "score": 40,
                "severity": "high",
                "reason": "test",
                "keywords": ["synthetic marker"],
            }]), encoding="utf-8")
            rules = load_rules(path)
            assessment = RiskScorer(rules).assess(
                Message("a", "b", "authorized-bus", "synthetic marker")
            )
            self.assertIn("TEST_SIGNAL", assessment.triggered_codes)

    def test_invalid_schema_cases_fail_closed(self):
        invalid_documents = [
            [{"code": "X", "score": 1, "severity": "low", "reason": "x"}],
            [{"code": "bad code", "score": 1, "severity": "low", "reason": "x", "keywords": ["x"]}],
            [{"code": "X", "score": "1", "severity": "low", "reason": "x", "keywords": ["x"]}],
            [{"code": "X", "score": 1, "severity": "weird", "reason": "x", "keywords": ["x"]}],
            [{"code": "X", "score": 1, "severity": "low", "reason": "x", "keywords": ["x"], "extra": True}],
        ]
        for data in invalid_documents:
            with self.subTest(data=data), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "rules.json"
                path.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_rules(path)

    def test_duplicate_codes_fail_closed(self):
        data = [
            {"code": "X", "score": 1, "severity": "low", "reason": "a", "keywords": ["a"]},
            {"code": "X", "score": 2, "severity": "medium", "reason": "b", "keywords": ["b"]},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_rules(path)


if __name__ == "__main__":
    unittest.main()

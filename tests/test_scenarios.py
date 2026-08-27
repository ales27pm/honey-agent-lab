import tempfile
import unittest

from honey_agent_lab.models import PolicyAction
from honey_agent_lab.orchestrator import run_scenario
from honey_agent_lab.scenarios import get_scenario, list_scenarios


class ScenarioTests(unittest.TestCase):
    def test_all_scenarios_are_registered(self):
        names = {scenario.name for scenario in list_scenarios()}
        self.assertEqual({"scenario_001", "scenario_002", "scenario_003", "scenario_004"}, names)
        self.assertEqual(get_scenario("scenario_001").name, "scenario_001")

    def test_scenario_001_quarantines(self):
        result = run_scenario("scenario_001")
        self.assertEqual(result.final_decision.action, PolicyAction.QUARANTINE)
        self.assertEqual(result.final_assessment.total_score, 100)
        self.assertTrue(result.ledger.verify_integrity())

    def test_scenario_002_quarantines(self):
        result = run_scenario("scenario_002")
        self.assertEqual(result.final_decision.action, PolicyAction.QUARANTINE)
        self.assertTrue(result.ledger.verify_integrity())

    def test_scenario_003_isolates(self):
        result = run_scenario("scenario_003")
        self.assertEqual(result.final_decision.action, PolicyAction.ISOLATE)
        self.assertTrue(result.ledger.verify_integrity())

    def test_scenario_004_allows(self):
        result = run_scenario("scenario_004")
        self.assertEqual(result.final_decision.action, PolicyAction.ALLOW)
        self.assertEqual(result.final_assessment.total_score, 0)
        self.assertTrue(result.ledger.verify_integrity())

    def test_audit_export(self):
        result = run_scenario("scenario_001")
        with tempfile.TemporaryDirectory() as tmp:
            path = result.write_audit(f"{tmp}/audit.jsonl")
            text = path.read_text(encoding="utf-8")
        self.assertIn("scenario_started", text)
        self.assertIn("quarantine_applied", text)


if __name__ == "__main__":
    unittest.main()
